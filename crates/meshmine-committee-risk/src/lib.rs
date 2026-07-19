//! Exact per-selection committee probabilities plus deterministic Monte Carlo
//! and numerically stable annualization. This is a parameter tool, not a source
//! of normative mainnet committee constants.

use std::cmp::Ordering;
use std::fmt;

use meshmine_hns::{Hash256, blake2b_256};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, ToPrimitive, Zero};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use thiserror::Error;

pub const SECONDS_PER_YEAR: u64 = 365 * 24 * 60 * 60;
pub const MAX_COMMITTEE_SIZE: u16 = 256;
pub const MAX_CORRELATION_GROUPS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExactProbability {
    pub numerator: BigUint,
    pub denominator: BigUint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EligiblePopulation {
    pub total_members: u32,
    pub adversarial_members: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleParameters {
    pub name: String,
    pub committee_size: u16,
    pub certificate_threshold: u16,
    pub opening_threshold: u16,
    pub eligible_population: Option<EligiblePopulation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorrelationGroup {
    /// Disjoint fraction of eligible selection weight in this failure domain.
    pub member_fraction: ExactProbability,
    /// Mutually exclusive whole-group outage probability per selection.
    pub outage_probability: ExactProbability,
    /// Mutually exclusive whole-group compromise probability per selection.
    pub compromise_probability: ExactProbability,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleOverlap {
    pub first_role: usize,
    pub second_role: usize,
    pub shared_members: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParallelLaneModel {
    IndependentCommittees,
    SharedCommittee,
}

#[derive(Clone, Debug)]
pub struct RiskProfile {
    pub adversarial_work_fraction: ExactProbability,
    /// Measured fraction after the configured finalized-work lookback. This
    /// makes work concentration/delayed eligibility an explicit input.
    pub eligible_adversarial_fraction: ExactProbability,
    pub member_online_probability: ExactProbability,
    pub correlation_groups: Vec<CorrelationGroup>,
    pub rotation_interval_seconds: u64,
    pub lookback_window_blocks: u32,
    pub minimum_lookback_blocks: u32,
    pub parallel_lanes: u16,
    pub lane_model: ParallelLaneModel,
    pub annual_security_target: f64,
    pub annual_liveness_target: f64,
    pub roles: Vec<RoleParameters>,
    pub overlaps: Vec<RoleOverlap>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProbabilityRisk {
    pub per_selection: ExactProbability,
    pub annual_any: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RoleRiskReport {
    pub name: String,
    pub committee_size: u16,
    pub certificate_threshold: u16,
    pub opening_threshold: u16,
    pub binomial_certificate_capture: ExactProbability,
    pub binomial_opening_capture: ExactProbability,
    pub hypergeometric_certificate_capture: Option<ExactProbability>,
    pub hypergeometric_opening_capture: Option<ExactProbability>,
    pub correlated_certificate_capture: ExactProbability,
    pub correlated_opening_capture: ExactProbability,
    pub adversarial_certificate_block: ExactProbability,
    pub adversarial_opening_block: ExactProbability,
    pub too_few_honest_online_for_certificate: ExactProbability,
    pub too_few_honest_online_for_opening: ExactProbability,
    pub combined_certificate_block: ExactProbability,
    pub combined_opening_block: ExactProbability,
    pub capture_risk: ProbabilityRisk,
    pub blocking_risk: ProbabilityRisk,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OverlapRiskReport {
    pub first_role: String,
    pub second_role: String,
    pub shared_members: u16,
    pub joint_certificate_capture: ExactProbability,
    pub independent_certificate_product: ExactProbability,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeploymentRiskReport {
    profile_commitment: Hash256,
    committee_selections_per_year: u64,
    eligibility_concentration_multiple: f64,
    role_reports: Vec<RoleRiskReport>,
    overlap_reports: Vec<OverlapRiskReport>,
    per_selection_capture_union_bound: ExactProbability,
    per_selection_blocking_union_bound: ExactProbability,
    annual_capture_union_bound_exact: ExactProbability,
    annual_blocking_union_bound_exact: ExactProbability,
    annual_capture_union_bound: f64,
    annual_blocking_union_bound: f64,
    security_target_met: bool,
    liveness_target_met: bool,
}

impl DeploymentRiskReport {
    pub const fn profile_commitment(&self) -> Hash256 {
        self.profile_commitment
    }

    pub const fn committee_selections_per_year(&self) -> u64 {
        self.committee_selections_per_year
    }

    pub const fn eligibility_concentration_multiple(&self) -> f64 {
        self.eligibility_concentration_multiple
    }

    pub fn role_reports(&self) -> &[RoleRiskReport] {
        &self.role_reports
    }

    pub fn overlap_reports(&self) -> &[OverlapRiskReport] {
        &self.overlap_reports
    }

    pub fn per_selection_capture_union_bound(&self) -> &ExactProbability {
        &self.per_selection_capture_union_bound
    }

    pub fn per_selection_blocking_union_bound(&self) -> &ExactProbability {
        &self.per_selection_blocking_union_bound
    }

    pub fn annual_capture_union_bound_exact(&self) -> &ExactProbability {
        &self.annual_capture_union_bound_exact
    }

    pub fn annual_blocking_union_bound_exact(&self) -> &ExactProbability {
        &self.annual_blocking_union_bound_exact
    }

    pub const fn annual_capture_union_bound(&self) -> f64 {
        self.annual_capture_union_bound
    }

    pub const fn annual_blocking_union_bound(&self) -> f64 {
        self.annual_blocking_union_bound
    }

    pub const fn security_target_met(&self) -> bool {
        self.security_target_met
    }

    pub const fn liveness_target_met(&self) -> bool {
        self.liveness_target_met
    }

    /// Return the unique canonical role profile bound into this report.
    /// Duplicate role names are rejected by profile validation, but keeping
    /// this lookup fail-closed also protects reports restored by future code.
    pub fn role(&self, name: &str) -> Option<&RoleRiskReport> {
        let mut matching = self.role_reports.iter().filter(|role| role.name == name);
        let role = matching.next()?;
        matching.next().is_none().then_some(role)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MonteCarloRoleReport {
    pub trials: u64,
    pub certificate_captures: u64,
    pub opening_captures: u64,
    pub certificate_blocks: u64,
    pub opening_blocks: u64,
}

#[derive(Debug, Error, PartialEq)]
pub enum RiskError {
    #[error("probability denominator must be nonzero")]
    ZeroDenominator,
    #[error("probability is outside [0,1]")]
    ProbabilityOutOfRange,
    #[error("profile has no role committees")]
    EmptyRoles,
    #[error("committee thresholds or eligible population are invalid")]
    InvalidCommittee,
    #[error("rotation interval and parallel lane count must be nonzero")]
    InvalidRotation,
    #[error("eligibility lookback is shorter than the configured minimum")]
    LookbackTooShort,
    #[error("correlation groups must be disjoint and have valid outcomes")]
    InvalidCorrelationGroups,
    #[error("role overlap definition is invalid")]
    InvalidRoleOverlap,
    #[error("annual probability bounds must be finite values in [0,1]")]
    InvalidAnnualTarget,
    #[error("parameter profile exceeds its annual security risk bound")]
    SecurityBoundExceeded,
    #[error("parameter profile exceeds its annual liveness risk bound")]
    LivenessBoundExceeded,
    #[error("Monte Carlo trial count must be nonzero")]
    ZeroTrials,
}

impl ExactProbability {
    pub fn new(
        numerator: impl Into<BigUint>,
        denominator: impl Into<BigUint>,
    ) -> Result<Self, RiskError> {
        let numerator = numerator.into();
        let denominator = denominator.into();
        if denominator.is_zero() {
            return Err(RiskError::ZeroDenominator);
        }
        if numerator > denominator {
            return Err(RiskError::ProbabilityOutOfRange);
        }
        Ok(Self::reduced(numerator, denominator))
    }

    pub fn zero() -> Self {
        Self {
            numerator: BigUint::zero(),
            denominator: BigUint::one(),
        }
    }

    pub fn one() -> Self {
        Self {
            numerator: BigUint::one(),
            denominator: BigUint::one(),
        }
    }

    pub fn from_ratio(numerator: u64, denominator: u64) -> Result<Self, RiskError> {
        Self::new(numerator, denominator)
    }

    pub fn complement(&self) -> Self {
        Self::reduced(
            &self.denominator - &self.numerator,
            self.denominator.clone(),
        )
    }

    pub fn add(&self, other: &Self) -> Self {
        let numerator = &self.numerator * &other.denominator + &other.numerator * &self.denominator;
        let denominator = &self.denominator * &other.denominator;
        let sum = Self::reduced(numerator, denominator);
        sum.capped_at_one()
    }

    pub fn subtract(&self, other: &Self) -> Self {
        assert!(self >= other);
        Self::reduced(
            &self.numerator * &other.denominator - &other.numerator * &self.denominator,
            &self.denominator * &other.denominator,
        )
    }

    pub fn multiply(&self, other: &Self) -> Self {
        Self::reduced(
            &self.numerator * &other.numerator,
            &self.denominator * &other.denominator,
        )
    }

    pub fn pow(&self, exponent: u32) -> Self {
        Self::reduced(self.numerator.pow(exponent), self.denominator.pow(exponent))
    }

    pub fn to_f64(&self) -> f64 {
        if self.numerator.is_zero() {
            return 0.0;
        }
        if self.numerator == self.denominator {
            return 1.0;
        }
        let numerator_shift = self.numerator.bits().saturating_sub(53) as usize;
        let denominator_shift = self.denominator.bits().saturating_sub(53) as usize;
        let numerator = (&self.numerator >> numerator_shift).to_f64().unwrap_or(0.0);
        let denominator = (&self.denominator >> denominator_shift)
            .to_f64()
            .unwrap_or(1.0);
        let exponent = i32::try_from(numerator_shift)
            .unwrap_or(i32::MAX)
            .saturating_sub(i32::try_from(denominator_shift).unwrap_or(i32::MAX));
        (numerator / denominator) * 2f64.powi(exponent)
    }

    fn reduced(numerator: BigUint, denominator: BigUint) -> Self {
        if numerator.is_zero() {
            return Self::zero();
        }
        let divisor = numerator.gcd(&denominator);
        Self {
            numerator: numerator / &divisor,
            denominator: denominator / divisor,
        }
    }

    fn capped_at_one(&self) -> Self {
        if self <= &Self::one() {
            self.clone()
        } else {
            Self::one()
        }
    }

    fn maximum(&self, other: &Self) -> Self {
        if self >= other {
            self.clone()
        } else {
            other.clone()
        }
    }
}

impl Ord for ExactProbability {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.numerator * &other.denominator).cmp(&(&other.numerator * &self.denominator))
    }
}

impl PartialOrd for ExactProbability {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for ExactProbability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.numerator, self.denominator)
    }
}

pub fn binomial_tail(
    trials: u16,
    at_least: u16,
    probability: &ExactProbability,
) -> ExactProbability {
    if at_least == 0 {
        return ExactProbability::one();
    }
    if at_least > trials {
        return ExactProbability::zero();
    }
    let mut result = ExactProbability::zero();
    for successes in at_least..=trials {
        result = result.add(&binomial_mass(trials, successes, probability));
    }
    result
}

pub fn hypergeometric_tail(
    population: &EligiblePopulation,
    draws: u16,
    at_least: u16,
) -> Result<ExactProbability, RiskError> {
    validate_population(population, draws)?;
    if at_least == 0 {
        return Ok(ExactProbability::one());
    }
    let denominator = choose(population.total_members, u32::from(draws));
    let minimum = u32::from(at_least);
    let maximum = u32::from(draws).min(population.adversarial_members);
    let honest = population.total_members - population.adversarial_members;
    let mut numerator = BigUint::zero();
    for adversarial in minimum..=maximum {
        let honest_draws = u32::from(draws) - adversarial;
        if honest_draws <= honest {
            numerator +=
                choose(population.adversarial_members, adversarial) * choose(honest, honest_draws);
        }
    }
    ExactProbability::new(numerator, denominator)
}

/// Canonical commitment to every deployment-risk input. The release layer
/// records this digest so a passing report cannot be detached from the exact
/// assumptions and committee policies that produced it.
pub fn risk_profile_commitment(profile: &RiskProfile) -> Result<Hash256, RiskError> {
    validate_profile(profile)?;
    Ok(risk_profile_commitment_validated(profile))
}

fn risk_profile_commitment_validated(profile: &RiskProfile) -> Hash256 {
    const DOMAIN: &[u8] = b"meshmine/committee-risk-profile/v2";
    let mut bytes = Vec::new();
    encode_probability_commitment(&mut bytes, &profile.adversarial_work_fraction);
    encode_probability_commitment(&mut bytes, &profile.eligible_adversarial_fraction);
    encode_probability_commitment(&mut bytes, &profile.member_online_probability);
    encode_len(&mut bytes, profile.correlation_groups.len());
    for group in &profile.correlation_groups {
        encode_probability_commitment(&mut bytes, &group.member_fraction);
        encode_probability_commitment(&mut bytes, &group.outage_probability);
        encode_probability_commitment(&mut bytes, &group.compromise_probability);
    }
    bytes.extend_from_slice(&profile.rotation_interval_seconds.to_le_bytes());
    bytes.extend_from_slice(&profile.lookback_window_blocks.to_le_bytes());
    bytes.extend_from_slice(&profile.minimum_lookback_blocks.to_le_bytes());
    bytes.extend_from_slice(&profile.parallel_lanes.to_le_bytes());
    bytes.push(match profile.lane_model {
        ParallelLaneModel::IndependentCommittees => 0,
        ParallelLaneModel::SharedCommittee => 1,
    });
    bytes.extend_from_slice(&canonical_bound_bits(profile.annual_security_target).to_le_bytes());
    bytes.extend_from_slice(&canonical_bound_bits(profile.annual_liveness_target).to_le_bytes());
    encode_len(&mut bytes, profile.roles.len());
    for role in &profile.roles {
        encode_len(&mut bytes, role.name.len());
        bytes.extend_from_slice(role.name.as_bytes());
        bytes.extend_from_slice(&role.committee_size.to_le_bytes());
        bytes.extend_from_slice(&role.certificate_threshold.to_le_bytes());
        bytes.extend_from_slice(&role.opening_threshold.to_le_bytes());
        match &role.eligible_population {
            Some(population) => {
                bytes.push(1);
                bytes.extend_from_slice(&population.total_members.to_le_bytes());
                bytes.extend_from_slice(&population.adversarial_members.to_le_bytes());
            }
            None => bytes.push(0),
        }
    }
    encode_len(&mut bytes, profile.overlaps.len());
    for overlap in &profile.overlaps {
        encode_len(&mut bytes, overlap.first_role);
        encode_len(&mut bytes, overlap.second_role);
        bytes.extend_from_slice(&overlap.shared_members.to_le_bytes());
    }
    blake2b_256(&[DOMAIN, &bytes])
}

fn encode_probability_commitment(bytes: &mut Vec<u8>, probability: &ExactProbability) {
    let numerator = probability.numerator.to_bytes_be();
    let denominator = probability.denominator.to_bytes_be();
    encode_len(bytes, numerator.len());
    bytes.extend_from_slice(&numerator);
    encode_len(bytes, denominator.len());
    bytes.extend_from_slice(&denominator);
}

fn encode_len(bytes: &mut Vec<u8>, length: usize) {
    bytes.extend_from_slice(&u64::try_from(length).unwrap_or(u64::MAX).to_le_bytes());
}

fn canonical_bound_bits(value: f64) -> u64 {
    if value == 0.0 { 0 } else { value.to_bits() }
}

pub fn assess_profile(profile: &RiskProfile) -> Result<DeploymentRiskReport, RiskError> {
    validate_profile(profile)?;
    let events = selections_per_year(profile);
    let mut role_reports = Vec::with_capacity(profile.roles.len());
    for role in &profile.roles {
        role_reports.push(assess_role(profile, role, events)?);
    }
    let overlap_reports = profile
        .overlaps
        .iter()
        .map(|overlap| assess_overlap(profile, overlap))
        .collect::<Result<Vec<_>, _>>()?;
    let capture_union = role_reports
        .iter()
        .fold(ExactProbability::zero(), |sum, role| {
            sum.add(&role.capture_risk.per_selection)
        });
    let blocking_union = role_reports
        .iter()
        .fold(ExactProbability::zero(), |sum, role| {
            sum.add(&role.blocking_risk.per_selection)
        });
    // Release authorization uses the exact Bonferroni bound across selections.
    // The independent-selection annualization retained in each role report is
    // presentation evidence only and must never decide a production gate.
    let annual_capture_union_bound_exact = annual_union_bound(&capture_union, events);
    let annual_blocking_union_bound_exact = annual_union_bound(&blocking_union, events);
    let annual_capture_union_bound = annual_capture_union_bound_exact.to_f64();
    let annual_blocking_union_bound = annual_blocking_union_bound_exact.to_f64();
    let security_target_met = meets_target(&capture_union, events, profile.annual_security_target);
    let liveness_target_met = meets_target(&blocking_union, events, profile.annual_liveness_target);
    Ok(DeploymentRiskReport {
        profile_commitment: risk_profile_commitment_validated(profile),
        committee_selections_per_year: events,
        eligibility_concentration_multiple: eligibility_concentration_multiple(profile),
        role_reports,
        overlap_reports,
        per_selection_capture_union_bound: capture_union,
        per_selection_blocking_union_bound: blocking_union,
        annual_capture_union_bound_exact,
        annual_blocking_union_bound_exact,
        annual_capture_union_bound,
        annual_blocking_union_bound,
        security_target_met,
        liveness_target_met,
    })
}

pub fn enforce_profile(profile: &RiskProfile) -> Result<DeploymentRiskReport, RiskError> {
    let report = assess_profile(profile)?;
    if !report.security_target_met {
        return Err(RiskError::SecurityBoundExceeded);
    }
    if !report.liveness_target_met {
        return Err(RiskError::LivenessBoundExceeded);
    }
    Ok(report)
}

pub fn monte_carlo_role(
    profile: &RiskProfile,
    role_index: usize,
    trials: u64,
    seed: [u8; 32],
) -> Result<MonteCarloRoleReport, RiskError> {
    validate_profile(profile)?;
    if trials == 0 {
        return Err(RiskError::ZeroTrials);
    }
    let role = profile
        .roles
        .get(role_index)
        .ok_or(RiskError::InvalidCommittee)?;
    let mut rng = ChaCha20Rng::from_seed(seed);
    let certificate_block_threshold = role.committee_size - role.certificate_threshold + 1;
    let opening_block_threshold = role.committee_size - role.opening_threshold + 1;
    let mut report = MonteCarloRoleReport {
        trials,
        certificate_captures: 0,
        opening_captures: 0,
        certificate_blocks: 0,
        opening_blocks: 0,
    };
    for _ in 0..trials {
        let (adversarial, honest_online) = sampled_effective_probabilities(profile, &mut rng);
        let (adversarial_count, honest_online_count) =
            sample_committee_categories(role.committee_size, adversarial, honest_online, &mut rng);
        report.certificate_captures += u64::from(adversarial_count >= role.certificate_threshold);
        report.opening_captures += u64::from(adversarial_count >= role.opening_threshold);
        report.certificate_blocks += u64::from(
            adversarial_count >= certificate_block_threshold
                || honest_online_count < role.certificate_threshold,
        );
        report.opening_blocks += u64::from(
            adversarial_count >= opening_block_threshold
                || honest_online_count < role.opening_threshold,
        );
    }
    Ok(report)
}

fn assess_role(
    profile: &RiskProfile,
    role: &RoleParameters,
    events: u64,
) -> Result<RoleRiskReport, RiskError> {
    let adversarial = &profile.eligible_adversarial_fraction;
    let binomial_certificate_capture =
        binomial_tail(role.committee_size, role.certificate_threshold, adversarial);
    let binomial_opening_capture =
        binomial_tail(role.committee_size, role.opening_threshold, adversarial);
    let hypergeometric_certificate_capture = role
        .eligible_population
        .as_ref()
        .map(|population| {
            hypergeometric_tail(population, role.committee_size, role.certificate_threshold)
        })
        .transpose()?;
    let hypergeometric_opening_capture = role
        .eligible_population
        .as_ref()
        .map(|population| {
            hypergeometric_tail(population, role.committee_size, role.opening_threshold)
        })
        .transpose()?;
    let correlated_certificate_capture = correlated_tail(
        profile,
        role.committee_size,
        role.certificate_threshold,
        TailKind::Adversarial,
    );
    let correlated_opening_capture = correlated_tail(
        profile,
        role.committee_size,
        role.opening_threshold,
        TailKind::Adversarial,
    );
    let certificate_block_threshold = role.committee_size - role.certificate_threshold + 1;
    let opening_block_threshold = role.committee_size - role.opening_threshold + 1;
    let adversarial_certificate_block = correlated_tail(
        profile,
        role.committee_size,
        certificate_block_threshold,
        TailKind::Adversarial,
    );
    let adversarial_opening_block = correlated_tail(
        profile,
        role.committee_size,
        opening_block_threshold,
        TailKind::Adversarial,
    );
    let too_few_honest_online_for_certificate = correlated_tail(
        profile,
        role.committee_size,
        role.certificate_threshold,
        TailKind::HonestOnlineFailure,
    );
    let too_few_honest_online_for_opening = correlated_tail(
        profile,
        role.committee_size,
        role.opening_threshold,
        TailKind::HonestOnlineFailure,
    );
    let combined_certificate_block = correlated_combined_block(
        profile,
        role.committee_size,
        certificate_block_threshold,
        role.certificate_threshold,
    );
    let combined_opening_block = correlated_combined_block(
        profile,
        role.committee_size,
        opening_block_threshold,
        role.opening_threshold,
    );

    let mut capture = correlated_certificate_capture.maximum(&correlated_opening_capture);
    if let Some(value) = &hypergeometric_certificate_capture {
        capture = capture.maximum(value);
    }
    if let Some(value) = &hypergeometric_opening_capture {
        capture = capture.maximum(value);
    }
    let blocking = combined_certificate_block.maximum(&combined_opening_block);
    Ok(RoleRiskReport {
        name: role.name.clone(),
        committee_size: role.committee_size,
        certificate_threshold: role.certificate_threshold,
        opening_threshold: role.opening_threshold,
        binomial_certificate_capture,
        binomial_opening_capture,
        hypergeometric_certificate_capture,
        hypergeometric_opening_capture,
        correlated_certificate_capture,
        correlated_opening_capture,
        adversarial_certificate_block,
        adversarial_opening_block,
        too_few_honest_online_for_certificate,
        too_few_honest_online_for_opening,
        combined_certificate_block,
        combined_opening_block,
        capture_risk: ProbabilityRisk {
            annual_any: annualize(&capture, events),
            per_selection: capture,
        },
        blocking_risk: ProbabilityRisk {
            annual_any: annualize(&blocking, events),
            per_selection: blocking,
        },
    })
}

fn assess_overlap(
    profile: &RiskProfile,
    overlap: &RoleOverlap,
) -> Result<OverlapRiskReport, RiskError> {
    let first = &profile.roles[overlap.first_role];
    let second = &profile.roles[overlap.second_role];
    let joint = correlated_joint_tail(
        profile,
        first,
        second,
        overlap.shared_members,
        first.certificate_threshold,
        second.certificate_threshold,
    );
    let independent = binomial_tail(
        first.committee_size,
        first.certificate_threshold,
        &profile.eligible_adversarial_fraction,
    )
    .multiply(&binomial_tail(
        second.committee_size,
        second.certificate_threshold,
        &profile.eligible_adversarial_fraction,
    ));
    Ok(OverlapRiskReport {
        first_role: first.name.clone(),
        second_role: second.name.clone(),
        shared_members: overlap.shared_members,
        joint_certificate_capture: joint,
        independent_certificate_product: independent,
    })
}

#[derive(Clone, Copy)]
enum GroupState {
    Normal,
    Outage,
    Compromised,
}

#[derive(Clone, Copy)]
enum TailKind {
    Adversarial,
    HonestOnlineFailure,
}

fn correlated_tail(
    profile: &RiskProfile,
    committee_size: u16,
    threshold: u16,
    kind: TailKind,
) -> ExactProbability {
    let mut result = ExactProbability::zero();
    visit_group_states(profile, |weight, compromised, outage| {
        let probability = match kind {
            TailKind::Adversarial => {
                let base_honest = profile.eligible_adversarial_fraction.complement();
                let effective = profile
                    .eligible_adversarial_fraction
                    .add(&base_honest.multiply(compromised));
                binomial_tail(committee_size, threshold, &effective)
            }
            TailKind::HonestOnlineFailure => {
                let unavailable_domain = compromised.add(outage);
                let honest_online = profile
                    .eligible_adversarial_fraction
                    .complement()
                    .multiply(&profile.member_online_probability)
                    .multiply(&unavailable_domain.complement());
                binomial_tail(committee_size, threshold, &honest_online).complement()
            }
        };
        result = result.add(&weight.multiply(&probability));
    });
    result
}

fn correlated_joint_tail(
    profile: &RiskProfile,
    first: &RoleParameters,
    second: &RoleParameters,
    shared: u16,
    first_threshold: u16,
    second_threshold: u16,
) -> ExactProbability {
    let mut result = ExactProbability::zero();
    visit_group_states(profile, |weight, compromised, _| {
        let base_honest = profile.eligible_adversarial_fraction.complement();
        let effective = profile
            .eligible_adversarial_fraction
            .add(&base_honest.multiply(compromised));
        let joint = joint_binomial_tail(
            first.committee_size,
            first_threshold,
            second.committee_size,
            second_threshold,
            shared,
            &effective,
        );
        result = result.add(&weight.multiply(&joint));
    });
    result
}

fn correlated_combined_block(
    profile: &RiskProfile,
    committee_size: u16,
    adversarial_block_threshold: u16,
    honest_online_threshold: u16,
) -> ExactProbability {
    let mut result = ExactProbability::zero();
    visit_group_states(profile, |weight, compromised, outage| {
        let base_honest = profile.eligible_adversarial_fraction.complement();
        let adversarial = profile
            .eligible_adversarial_fraction
            .add(&base_honest.multiply(compromised));
        let unavailable_domain = compromised.add(outage);
        let honest_online = base_honest
            .multiply(&profile.member_online_probability)
            .multiply(&unavailable_domain.complement());
        let block = categorical_block_probability(
            committee_size,
            adversarial_block_threshold,
            honest_online_threshold,
            &adversarial,
            &honest_online,
        );
        result = result.add(&weight.multiply(&block));
    });
    result
}

fn categorical_block_probability(
    committee_size: u16,
    adversarial_block_threshold: u16,
    honest_online_threshold: u16,
    adversarial: &ExactProbability,
    honest_online: &ExactProbability,
) -> ExactProbability {
    let other = adversarial.add(honest_online).complement();
    let mut result = ExactProbability::zero();
    for adversarial_count in 0..=committee_size {
        for honest_online_count in 0..=committee_size - adversarial_count {
            if adversarial_count < adversarial_block_threshold
                && honest_online_count >= honest_online_threshold
            {
                continue;
            }
            let other_count = committee_size - adversarial_count - honest_online_count;
            let combinations = choose(u32::from(committee_size), u32::from(adversarial_count))
                * choose(
                    u32::from(committee_size - adversarial_count),
                    u32::from(honest_online_count),
                );
            let mass = ExactProbability::reduced(
                combinations
                    * adversarial.numerator.pow(u32::from(adversarial_count))
                    * honest_online.numerator.pow(u32::from(honest_online_count))
                    * other.numerator.pow(u32::from(other_count)),
                adversarial.denominator.pow(u32::from(adversarial_count))
                    * honest_online
                        .denominator
                        .pow(u32::from(honest_online_count))
                    * other.denominator.pow(u32::from(other_count)),
            );
            result = result.add(&mass);
        }
    }
    result
}

fn joint_binomial_tail(
    first_size: u16,
    first_threshold: u16,
    second_size: u16,
    second_threshold: u16,
    shared: u16,
    probability: &ExactProbability,
) -> ExactProbability {
    let mut result = ExactProbability::zero();
    for shared_adversarial in 0..=shared {
        let shared_mass = binomial_mass(shared, shared_adversarial, probability);
        let first_needed = first_threshold.saturating_sub(shared_adversarial);
        let second_needed = second_threshold.saturating_sub(shared_adversarial);
        let first_tail = binomial_tail(first_size - shared, first_needed, probability);
        let second_tail = binomial_tail(second_size - shared, second_needed, probability);
        result = result.add(&shared_mass.multiply(&first_tail).multiply(&second_tail));
    }
    result
}

fn visit_group_states(
    profile: &RiskProfile,
    mut visitor: impl FnMut(&ExactProbability, &ExactProbability, &ExactProbability),
) {
    fn recurse(
        groups: &[CorrelationGroup],
        index: usize,
        weight: ExactProbability,
        compromised: ExactProbability,
        outage: ExactProbability,
        visitor: &mut impl FnMut(&ExactProbability, &ExactProbability, &ExactProbability),
    ) {
        if index == groups.len() {
            visitor(&weight, &compromised, &outage);
            return;
        }
        let group = &groups[index];
        let normal_probability = group
            .outage_probability
            .add(&group.compromise_probability)
            .complement();
        for (state, state_probability) in [
            (GroupState::Normal, normal_probability),
            (GroupState::Outage, group.outage_probability.clone()),
            (
                GroupState::Compromised,
                group.compromise_probability.clone(),
            ),
        ] {
            if state_probability == ExactProbability::zero() {
                continue;
            }
            let mut next_compromised = compromised.clone();
            let mut next_outage = outage.clone();
            match state {
                GroupState::Normal => {}
                GroupState::Outage => next_outage = next_outage.add(&group.member_fraction),
                GroupState::Compromised => {
                    next_compromised = next_compromised.add(&group.member_fraction)
                }
            }
            recurse(
                groups,
                index + 1,
                weight.multiply(&state_probability),
                next_compromised,
                next_outage,
                visitor,
            );
        }
    }
    recurse(
        &profile.correlation_groups,
        0,
        ExactProbability::one(),
        ExactProbability::zero(),
        ExactProbability::zero(),
        &mut visitor,
    );
}

fn sampled_effective_probabilities(profile: &RiskProfile, rng: &mut ChaCha20Rng) -> (f64, f64) {
    let mut compromised = 0.0;
    let mut outage = 0.0;
    for group in &profile.correlation_groups {
        let draw = rng.random::<f64>();
        let compromise = group.compromise_probability.to_f64();
        let down = group.outage_probability.to_f64();
        if draw < compromise {
            compromised += group.member_fraction.to_f64();
        } else if draw < compromise + down {
            outage += group.member_fraction.to_f64();
        }
    }
    let adversarial = profile.eligible_adversarial_fraction.to_f64();
    let effective_adversarial = adversarial + (1.0 - adversarial) * compromised;
    let honest_online = (1.0 - adversarial)
        * profile.member_online_probability.to_f64()
        * (1.0 - compromised - outage);
    (effective_adversarial, honest_online)
}

fn sample_committee_categories(
    committee_size: u16,
    adversarial_probability: f64,
    honest_online_probability: f64,
    rng: &mut ChaCha20Rng,
) -> (u16, u16) {
    let mut adversarial = 0;
    let mut honest_online = 0;
    for _ in 0..committee_size {
        let draw = rng.random::<f64>();
        if draw < adversarial_probability {
            adversarial += 1;
        } else if draw < adversarial_probability + honest_online_probability {
            honest_online += 1;
        }
    }
    (adversarial, honest_online)
}

fn binomial_mass(trials: u16, successes: u16, probability: &ExactProbability) -> ExactProbability {
    if successes > trials {
        return ExactProbability::zero();
    }
    let combinations = choose(u32::from(trials), u32::from(successes));
    let numerator = combinations
        * probability.numerator.pow(u32::from(successes))
        * (&probability.denominator - &probability.numerator).pow(u32::from(trials - successes));
    let denominator = probability.denominator.pow(u32::from(trials));
    ExactProbability::reduced(numerator, denominator)
}

fn choose(n: u32, k: u32) -> BigUint {
    if k > n {
        return BigUint::zero();
    }
    let k = k.min(n - k);
    let mut value = BigUint::one();
    for index in 0..k {
        value *= n - index;
        value /= index + 1;
    }
    value
}

fn annualize(probability: &ExactProbability, events: u64) -> f64 {
    let per_event = probability.to_f64();
    if per_event <= 0.0 || events == 0 {
        return 0.0;
    }
    if per_event >= 1.0 {
        return 1.0;
    }
    -((events as f64) * (-per_event).ln_1p()).exp_m1()
}

fn annual_union_bound(probability: &ExactProbability, events: u64) -> ExactProbability {
    if probability.numerator.is_zero() || events == 0 {
        return ExactProbability::zero();
    }
    let numerator = &probability.numerator * BigUint::from(events);
    if numerator >= probability.denominator {
        ExactProbability::one()
    } else {
        ExactProbability::reduced(numerator, probability.denominator.clone())
    }
}

fn meets_target(probability: &ExactProbability, events: u64, target: f64) -> bool {
    annual_union_bound(probability, events) <= exact_f64_probability(target)
}

fn exact_f64_probability(value: f64) -> ExactProbability {
    debug_assert!(valid_bound(value));
    if value == 0.0 {
        return ExactProbability::zero();
    }
    if value == 1.0 {
        return ExactProbability::one();
    }
    let bits = value.to_bits();
    let exponent_bits = ((bits >> 52) & 0x7ff) as i32;
    let fraction = bits & ((1u64 << 52) - 1);
    let (significand, exponent) = if exponent_bits == 0 {
        (fraction, -1_074)
    } else {
        (fraction | (1u64 << 52), exponent_bits - 1_023 - 52)
    };
    if exponent >= 0 {
        ExactProbability::reduced(
            BigUint::from(significand) << usize::try_from(exponent).unwrap_or(usize::MAX),
            BigUint::one(),
        )
    } else {
        ExactProbability::reduced(
            BigUint::from(significand),
            BigUint::one() << usize::try_from(-exponent).unwrap_or(usize::MAX),
        )
    }
}

fn eligibility_concentration_multiple(profile: &RiskProfile) -> f64 {
    let work = profile.adversarial_work_fraction.to_f64();
    let eligible = profile.eligible_adversarial_fraction.to_f64();
    if work == 0.0 {
        if eligible == 0.0 { 1.0 } else { f64::INFINITY }
    } else {
        eligible / work
    }
}

fn selections_per_year(profile: &RiskProfile) -> u64 {
    let rotations = SECONDS_PER_YEAR.div_ceil(profile.rotation_interval_seconds);
    match profile.lane_model {
        ParallelLaneModel::IndependentCommittees => {
            rotations.saturating_mul(u64::from(profile.parallel_lanes))
        }
        ParallelLaneModel::SharedCommittee => rotations,
    }
}

fn validate_profile(profile: &RiskProfile) -> Result<(), RiskError> {
    validate_probability(&profile.adversarial_work_fraction)?;
    validate_probability(&profile.eligible_adversarial_fraction)?;
    validate_probability(&profile.member_online_probability)?;
    if profile.roles.is_empty() {
        return Err(RiskError::EmptyRoles);
    }
    if profile.rotation_interval_seconds == 0 || profile.parallel_lanes == 0 {
        return Err(RiskError::InvalidRotation);
    }
    if profile.lookback_window_blocks < profile.minimum_lookback_blocks {
        return Err(RiskError::LookbackTooShort);
    }
    if !valid_bound(profile.annual_security_target) || !valid_bound(profile.annual_liveness_target)
    {
        return Err(RiskError::InvalidAnnualTarget);
    }
    for (index, role) in profile.roles.iter().enumerate() {
        if role.name.is_empty()
            || profile.roles[..index]
                .iter()
                .any(|prior| prior.name == role.name)
            || role.committee_size == 0
            || role.committee_size > MAX_COMMITTEE_SIZE
            || role.certificate_threshold == 0
            || role.certificate_threshold > role.committee_size
            || role.opening_threshold == 0
            || role.opening_threshold > role.committee_size
        {
            return Err(RiskError::InvalidCommittee);
        }
        if let Some(population) = &role.eligible_population {
            validate_population(population, role.committee_size)?;
        }
    }
    if profile.correlation_groups.len() > MAX_CORRELATION_GROUPS {
        return Err(RiskError::InvalidCorrelationGroups);
    }
    let mut group_fraction = ExactProbability::zero();
    for group in &profile.correlation_groups {
        validate_probability(&group.member_fraction)?;
        validate_probability(&group.outage_probability)?;
        validate_probability(&group.compromise_probability)?;
        if probability_sum_exceeds_one(&group.outage_probability, &group.compromise_probability) {
            return Err(RiskError::InvalidCorrelationGroups);
        }
        if probability_sum_exceeds_one(&group_fraction, &group.member_fraction) {
            return Err(RiskError::InvalidCorrelationGroups);
        }
        group_fraction = group_fraction.add(&group.member_fraction);
    }
    if group_fraction > ExactProbability::one() {
        return Err(RiskError::InvalidCorrelationGroups);
    }
    for overlap in &profile.overlaps {
        if overlap.first_role >= profile.roles.len()
            || overlap.second_role >= profile.roles.len()
            || overlap.first_role == overlap.second_role
            || overlap.shared_members
                > profile.roles[overlap.first_role]
                    .committee_size
                    .min(profile.roles[overlap.second_role].committee_size)
        {
            return Err(RiskError::InvalidRoleOverlap);
        }
    }
    Ok(())
}

fn validate_probability(probability: &ExactProbability) -> Result<(), RiskError> {
    if probability.denominator.is_zero() {
        return Err(RiskError::ZeroDenominator);
    }
    if probability.numerator > probability.denominator {
        return Err(RiskError::ProbabilityOutOfRange);
    }
    Ok(())
}

fn validate_population(population: &EligiblePopulation, draws: u16) -> Result<(), RiskError> {
    if population.total_members == 0
        || population.adversarial_members > population.total_members
        || u32::from(draws) > population.total_members
    {
        return Err(RiskError::InvalidCommittee);
    }
    Ok(())
}

fn valid_bound(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

fn probability_sum_exceeds_one(first: &ExactProbability, second: &ExactProbability) -> bool {
    &first.numerator * &second.denominator + &second.numerator * &first.denominator
        > &first.denominator * &second.denominator
}

#[cfg(test)]
mod tests;
