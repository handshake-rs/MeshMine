use std::error::Error;
use std::{env, fs, process};

use meshmine_committee_risk::{
    CorrelationGroup, EligiblePopulation, ExactProbability, ParallelLaneModel, RiskProfile,
    RoleOverlap, RoleParameters, assess_profile, enforce_profile, monte_carlo_role,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProfile {
    adversarial_work_fraction: String,
    eligible_adversarial_fraction: String,
    member_online_probability: String,
    #[serde(default)]
    correlation_groups: Vec<WireCorrelationGroup>,
    rotation_interval_seconds: u64,
    lookback_window_blocks: u32,
    minimum_lookback_blocks: u32,
    parallel_lanes: u16,
    lane_model: String,
    annual_security_target: f64,
    annual_liveness_target: f64,
    roles: Vec<WireRole>,
    #[serde(default)]
    overlaps: Vec<WireOverlap>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCorrelationGroup {
    member_fraction: String,
    outage_probability: String,
    compromise_probability: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRole {
    name: String,
    committee_size: u16,
    certificate_threshold: u16,
    opening_threshold: u16,
    eligible_population: Option<WirePopulation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePopulation {
    total_members: u32,
    adversarial_members: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireOverlap {
    first_role: usize,
    second_role: usize,
    shared_members: u16,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("meshmine-committee-risk: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<_> = env::args().skip(1).collect();
    let (profile, enforce, monte_carlo_trials) = match arguments.first().map(String::as_str) {
        None | Some("example") => (illustrative_profile()?, false, None),
        Some("evaluate") => {
            let path = argument(&arguments, "--config")?;
            let wire: WireProfile = serde_json::from_str(&fs::read_to_string(path)?)?;
            let enforce = arguments.iter().any(|argument| argument == "--enforce");
            let monte_carlo_trials: Option<u64> = optional_argument(&arguments, "--monte-carlo")
                .map(str::parse)
                .transpose()?;
            (wire.try_into()?, enforce, monte_carlo_trials)
        }
        _ => {
            return Err(
                "usage: meshmine-committee-risk [example | evaluate --config FILE [--enforce] [--monte-carlo TRIALS]]"
                    .into(),
            );
        }
    };

    let report = assess_profile(&profile)?;
    print_report(&profile, &report);
    if let Some(trials) = monte_carlo_trials {
        for (index, role) in profile.roles.iter().enumerate() {
            let mut seed = [0; 32];
            seed[..8].copy_from_slice(&(index as u64).to_le_bytes());
            seed[8..16].copy_from_slice(&trials.to_le_bytes());
            let simulation = monte_carlo_role(&profile, index, trials, seed)?;
            println!(
                "monte_carlo role={} trials={} certificate_capture={:.12e} opening_capture={:.12e} certificate_block={:.12e} opening_block={:.12e}",
                role.name,
                trials,
                simulation.certificate_captures as f64 / trials as f64,
                simulation.opening_captures as f64 / trials as f64,
                simulation.certificate_blocks as f64 / trials as f64,
                simulation.opening_blocks as f64 / trials as f64,
            );
        }
    }
    if enforce {
        enforce_profile(&profile)?;
        println!("profile_enforced=true");
    }
    Ok(())
}

fn print_report(profile: &RiskProfile, report: &meshmine_committee_risk::DeploymentRiskReport) {
    println!(
        "profile_bounds_met={}",
        report.security_target_met() && report.liveness_target_met()
    );
    println!(
        "selections_per_year={}",
        report.committee_selections_per_year()
    );
    println!(
        "eligibility_concentration_multiple={:.8}",
        report.eligibility_concentration_multiple()
    );
    println!(
        "risk_profile_commitment={}",
        hex::encode(report.profile_commitment())
    );
    for role in report.role_reports() {
        println!(
            "role={} capture_per_selection={:.12e} capture_annual={:.12e} blocking_per_selection={:.12e} blocking_annual={:.12e}",
            role.name,
            role.capture_risk.per_selection.to_f64(),
            role.capture_risk.annual_any,
            role.blocking_risk.per_selection.to_f64(),
            role.blocking_risk.annual_any,
        );
    }
    for overlap in report.overlap_reports() {
        println!(
            "overlap first={} second={} shared={} joint_capture={:.12e} independent_product={:.12e}",
            overlap.first_role,
            overlap.second_role,
            overlap.shared_members,
            overlap.joint_certificate_capture.to_f64(),
            overlap.independent_certificate_product.to_f64(),
        );
    }
    println!(
        "deployment_capture_annual_upper={:.12e} exact={} target={:.12e} met={}",
        report.annual_capture_union_bound(),
        report.annual_capture_union_bound_exact(),
        profile.annual_security_target,
        report.security_target_met()
    );
    println!(
        "deployment_blocking_annual_upper={:.12e} exact={} target={:.12e} met={}",
        report.annual_blocking_union_bound(),
        report.annual_blocking_union_bound_exact(),
        profile.annual_liveness_target,
        report.liveness_target_met()
    );
}

fn illustrative_profile() -> Result<RiskProfile, Box<dyn Error>> {
    let role = |name: &str| RoleParameters {
        name: name.to_owned(),
        committee_size: 32,
        certificate_threshold: 23,
        opening_threshold: 21,
        eligible_population: None,
    };
    Ok(RiskProfile {
        adversarial_work_fraction: ratio("1/5")?,
        eligible_adversarial_fraction: ratio("1/5")?,
        member_online_probability: ratio("99/100")?,
        correlation_groups: vec![],
        rotation_interval_seconds: 86_400,
        lookback_window_blocks: 2_016,
        minimum_lookback_blocks: 1_008,
        parallel_lanes: 4,
        lane_model: ParallelLaneModel::IndependentCommittees,
        annual_security_target: 1e-6,
        annual_liveness_target: 1e-3,
        roles: ["mask", "receipt", "availability", "settlement"]
            .into_iter()
            .map(role)
            .collect(),
        overlaps: vec![RoleOverlap {
            first_role: 0,
            second_role: 1,
            shared_members: 4,
        }],
    })
}

impl TryFrom<WireProfile> for RiskProfile {
    type Error = Box<dyn Error>;

    fn try_from(wire: WireProfile) -> Result<Self, Self::Error> {
        let lane_model = match wire.lane_model.as_str() {
            "independent" => ParallelLaneModel::IndependentCommittees,
            "shared" => ParallelLaneModel::SharedCommittee,
            _ => return Err("lane_model must be 'independent' or 'shared'".into()),
        };
        Ok(Self {
            adversarial_work_fraction: ratio(&wire.adversarial_work_fraction)?,
            eligible_adversarial_fraction: ratio(&wire.eligible_adversarial_fraction)?,
            member_online_probability: ratio(&wire.member_online_probability)?,
            correlation_groups: wire
                .correlation_groups
                .into_iter()
                .map(|group| {
                    Ok(CorrelationGroup {
                        member_fraction: ratio(&group.member_fraction)?,
                        outage_probability: ratio(&group.outage_probability)?,
                        compromise_probability: ratio(&group.compromise_probability)?,
                    })
                })
                .collect::<Result<_, Box<dyn Error>>>()?,
            rotation_interval_seconds: wire.rotation_interval_seconds,
            lookback_window_blocks: wire.lookback_window_blocks,
            minimum_lookback_blocks: wire.minimum_lookback_blocks,
            parallel_lanes: wire.parallel_lanes,
            lane_model,
            annual_security_target: wire.annual_security_target,
            annual_liveness_target: wire.annual_liveness_target,
            roles: wire
                .roles
                .into_iter()
                .map(|role| RoleParameters {
                    name: role.name,
                    committee_size: role.committee_size,
                    certificate_threshold: role.certificate_threshold,
                    opening_threshold: role.opening_threshold,
                    eligible_population: role.eligible_population.map(|population| {
                        EligiblePopulation {
                            total_members: population.total_members,
                            adversarial_members: population.adversarial_members,
                        }
                    }),
                })
                .collect(),
            overlaps: wire
                .overlaps
                .into_iter()
                .map(|overlap| RoleOverlap {
                    first_role: overlap.first_role,
                    second_role: overlap.second_role,
                    shared_members: overlap.shared_members,
                })
                .collect(),
        })
    }
}

fn ratio(value: &str) -> Result<ExactProbability, Box<dyn Error>> {
    let (numerator, denominator) = value
        .split_once('/')
        .ok_or("probabilities must use exact 'numerator/denominator' syntax")?;
    Ok(ExactProbability::from_ratio(
        numerator.parse()?,
        denominator.parse()?,
    )?)
}

fn argument<'a>(arguments: &'a [String], name: &str) -> Result<&'a str, Box<dyn Error>> {
    optional_argument(arguments, name).ok_or_else(|| format!("missing {name}").into())
}

fn optional_argument<'a>(arguments: &'a [String], name: &str) -> Option<&'a str> {
    arguments
        .windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].as_str())
}
