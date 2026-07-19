use super::*;

fn p(numerator: u64, denominator: u64) -> ExactProbability {
    ExactProbability::from_ratio(numerator, denominator).unwrap()
}

fn role(name: &str, size: u16, sign: u16, open: u16) -> RoleParameters {
    RoleParameters {
        name: name.to_owned(),
        committee_size: size,
        certificate_threshold: sign,
        opening_threshold: open,
        eligible_population: Some(EligiblePopulation {
            total_members: 100,
            adversarial_members: 20,
        }),
    }
}

fn profile() -> RiskProfile {
    RiskProfile {
        adversarial_work_fraction: p(1, 5),
        eligible_adversarial_fraction: p(1, 5),
        member_online_probability: p(99, 100),
        correlation_groups: vec![],
        rotation_interval_seconds: 86_400,
        lookback_window_blocks: 2_016,
        minimum_lookback_blocks: 1_008,
        parallel_lanes: 2,
        lane_model: ParallelLaneModel::IndependentCommittees,
        annual_security_target: 1.0,
        annual_liveness_target: 1.0,
        roles: vec![
            role("mask", 16, 11, 9),
            role("receipt", 16, 11, 11),
            role("availability", 16, 11, 11),
            role("settlement", 16, 11, 11),
        ],
        overlaps: vec![RoleOverlap {
            first_role: 0,
            second_role: 1,
            shared_members: 4,
        }],
    }
}

#[test]
fn exact_binomial_and_hypergeometric_known_values_match() {
    assert_eq!(binomial_tail(3, 2, &p(1, 2)), p(1, 2));
    assert_eq!(
        hypergeometric_tail(
            &EligiblePopulation {
                total_members: 10,
                adversarial_members: 3,
            },
            4,
            2,
        )
        .unwrap(),
        p(1, 3)
    );
}

#[test]
fn reports_all_roles_annual_risks_overlap_and_parallel_lanes() {
    let profile = profile();
    let report = assess_profile(&profile).unwrap();
    assert_eq!(
        report.profile_commitment,
        risk_profile_commitment(&profile).unwrap()
    );
    assert_eq!(report.role_reports.len(), 4);
    assert_eq!(report.role_reports[0].committee_size, 16);
    assert_eq!(report.overlap_reports.len(), 1);
    assert_eq!(report.committee_selections_per_year, 730);
    assert!(report.annual_capture_union_bound > 0.0);
    assert!(report.annual_blocking_union_bound > 0.0);
    assert_eq!(
        report.annual_capture_union_bound,
        report.annual_capture_union_bound_exact.to_f64()
    );
    assert_eq!(
        report.annual_blocking_union_bound,
        report.annual_blocking_union_bound_exact.to_f64()
    );
    assert!(
        report.overlap_reports[0].joint_certificate_capture
            > report.overlap_reports[0].independent_certificate_product
    );

    let mut shared = profile.clone();
    shared.lane_model = ParallelLaneModel::SharedCommittee;
    let shared = assess_profile(&shared).unwrap();
    assert_eq!(shared.committee_selections_per_year, 365);
    assert!(shared.annual_capture_union_bound < report.annual_capture_union_bound);
}

#[test]
fn risk_profile_commitment_binds_policy_and_role_names_are_unique() {
    let baseline = profile();
    let baseline_commitment = risk_profile_commitment(&baseline).unwrap();
    assert_eq!(
        baseline_commitment,
        risk_profile_commitment(&baseline).unwrap()
    );

    let mut changed = baseline.clone();
    changed.roles[0].certificate_threshold += 1;
    assert_ne!(
        baseline_commitment,
        risk_profile_commitment(&changed).unwrap()
    );

    let mut duplicate = baseline;
    duplicate.roles[1].name = duplicate.roles[0].name.clone();
    assert_eq!(assess_profile(&duplicate), Err(RiskError::InvalidCommittee));
}

#[test]
fn correlated_compromise_and_outage_increase_reported_risk() {
    let baseline = assess_profile(&profile()).unwrap();
    let mut correlated_profile = profile();
    correlated_profile
        .correlation_groups
        .push(CorrelationGroup {
            member_fraction: p(1, 4),
            outage_probability: p(1, 100),
            compromise_probability: p(1, 200),
        });
    let correlated = assess_profile(&correlated_profile).unwrap();
    assert!(
        correlated.role_reports[0].correlated_certificate_capture
            > baseline.role_reports[0].correlated_certificate_capture
    );
    assert!(
        correlated.role_reports[0].too_few_honest_online_for_certificate
            > baseline.role_reports[0].too_few_honest_online_for_certificate
    );
}

#[test]
fn deterministic_monte_carlo_tracks_exact_correlated_model() {
    let mut profile = profile();
    profile.correlation_groups.push(CorrelationGroup {
        member_fraction: p(1, 5),
        outage_probability: p(1, 50),
        compromise_probability: p(1, 100),
    });
    let exact = assess_profile(&profile).unwrap();
    let simulation = monte_carlo_role(&profile, 0, 200_000, [42; 32]).unwrap();
    let observed = simulation.certificate_captures as f64 / simulation.trials as f64;
    let expected = exact.role_reports[0]
        .correlated_certificate_capture
        .to_f64();
    assert!(
        (observed - expected).abs() < 0.003,
        "{observed} vs {expected}"
    );
    let observed_block = simulation.certificate_blocks as f64 / simulation.trials as f64;
    let exact_block = exact.role_reports[0].combined_certificate_block.to_f64();
    assert!((observed_block - exact_block).abs() < 0.01);
}

#[test]
fn risk_bounds_and_short_lookback_reject_profiles() {
    let mut bounded = profile();
    bounded.annual_security_target = 0.0;
    assert_eq!(
        enforce_profile(&bounded),
        Err(RiskError::SecurityBoundExceeded)
    );
    bounded.annual_security_target = 1.0;
    bounded.annual_liveness_target = 0.0;
    assert_eq!(
        enforce_profile(&bounded),
        Err(RiskError::LivenessBoundExceeded)
    );
    bounded.annual_liveness_target = 1.0;
    bounded.lookback_window_blocks = 1_007;
    assert_eq!(assess_profile(&bounded), Err(RiskError::LookbackTooShort));
}

#[test]
fn eligible_concentration_is_explicit_and_changes_capture_risk() {
    let baseline = assess_profile(&profile()).unwrap();
    let mut concentrated = profile();
    concentrated.eligible_adversarial_fraction = p(3, 10);
    for role in &mut concentrated.roles {
        role.eligible_population = None;
    }
    let concentrated = assess_profile(&concentrated).unwrap();
    assert!(
        concentrated.role_reports[0].capture_risk.per_selection
            > baseline.role_reports[0].capture_risk.per_selection
    );
    assert!((concentrated.eligibility_concentration_multiple - 1.5).abs() < 1e-12);
}

#[test]
fn tiny_exact_probabilities_convert_without_common_scale_underflow() {
    let tiny = ExactProbability::new(BigUint::one(), BigUint::one() << 1_000usize).unwrap();
    assert!(tiny.to_f64() > 0.0);
    assert!(tiny.to_f64() < 1e-300);
}

#[test]
fn release_gate_uses_an_exact_conservative_annual_union_bound() {
    let per_selection = p(1, 10);
    assert!(annualize(&per_selection, 2) < 0.195);
    assert_eq!(annual_union_bound(&per_selection, 2), p(1, 5));
    assert!(!meets_target(&per_selection, 2, 0.195));
    assert!(meets_target(&per_selection, 2, 0.2));

    let minimum_subnormal = f64::from_bits(1);
    assert_eq!(
        exact_f64_probability(minimum_subnormal),
        ExactProbability::new(BigUint::one(), BigUint::one() << 1_074usize).unwrap()
    );
    let rounds_down_to_the_target =
        ExactProbability::new(BigUint::from(5u8), BigUint::one() << 1_076usize).unwrap();
    assert!(rounds_down_to_the_target.to_f64() <= minimum_subnormal);
    assert!(annualize(&rounds_down_to_the_target, 1) <= minimum_subnormal);
    assert!(!meets_target(
        &rounds_down_to_the_target,
        1,
        minimum_subnormal
    ));
}

#[test]
fn invalid_or_explosive_correlation_inputs_are_bounded() {
    let mut invalid = profile();
    invalid.correlation_groups = vec![CorrelationGroup {
        member_fraction: p(1, 2),
        outage_probability: p(3, 4),
        compromise_probability: p(1, 2),
    }];
    assert_eq!(
        assess_profile(&invalid),
        Err(RiskError::InvalidCorrelationGroups)
    );

    invalid.correlation_groups = (0..=MAX_CORRELATION_GROUPS)
        .map(|_| CorrelationGroup {
            member_fraction: p(0, 1),
            outage_probability: p(0, 1),
            compromise_probability: p(0, 1),
        })
        .collect();
    assert_eq!(
        assess_profile(&invalid),
        Err(RiskError::InvalidCorrelationGroups)
    );
}
