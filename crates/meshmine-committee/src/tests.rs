use ed25519_dalek::SigningKey;
use meshmine_committee_risk::{
    ExactProbability, ParallelLaneModel, RiskProfile, RoleParameters, enforce_profile,
};
use meshmine_crypto::{assemble_ed25519_set, sign_certificate};
use meshmine_types::{CORE_V2, OperatorRecordV2, SignatureBytes};

use super::*;

fn hash(byte: u8) -> Hash256 {
    [byte; 32]
}

fn amount(value: u64) -> U512 {
    let mut bytes = [0; 64];
    bytes[56..].copy_from_slice(&value.to_be_bytes());
    U512(bytes)
}

fn keys() -> Vec<SigningKey> {
    (1..=20)
        .map(|byte| SigningKey::from_bytes(&[byte; 32]))
        .collect()
}

fn snapshot(finalized_at_height: u32) -> EligibilitySnapshot {
    EligibilitySnapshot::build(
        CORE_V2,
        2,
        1,
        1,
        finalized_at_height - 10,
        finalized_at_height,
        keys()
            .iter()
            .enumerate()
            .map(|(index, key)| EligibilityLeaf {
                operator_pubkey: key.verifying_key().to_bytes(),
                finalized_work: amount((index + 1) as u64),
                eligible_role_mask: 0x0f,
            })
            .collect(),
    )
    .unwrap()
}

fn context(epoch: u64, anchor: u32, entropy: u8) -> SelectionContext {
    SelectionContext {
        epoch,
        selection_anchor_height: anchor,
        entropy_start_height: anchor - 2,
        delayed_hns_entropy: vec![hash(entropy), hash(entropy + 1)],
        prior_threshold_beacon: hash(90),
    }
}

fn policy() -> SelectionPolicy {
    SelectionPolicy {
        committee_size: 5,
        certificate_threshold: 3,
        opening_threshold: 4,
        minimum_lookback_blocks: 20,
        hybrid_static_seats: 2,
    }
}

fn schedule() -> BootstrapSchedule {
    BootstrapSchedule {
        hybrid_start_epoch: 2,
        dynamic_start_epoch: 4,
    }
}

fn bootstrap() -> Vec<[u8; 32]> {
    keys()
        .iter()
        .take(5)
        .map(|key| key.verifying_key().to_bytes())
        .collect()
}

fn release_risk_profile(
    committee_size: u16,
    certificate_threshold: u16,
    opening_threshold: u16,
) -> RiskProfile {
    RiskProfile {
        adversarial_work_fraction: ExactProbability::zero(),
        eligible_adversarial_fraction: ExactProbability::zero(),
        member_online_probability: ExactProbability::one(),
        correlation_groups: vec![],
        rotation_interval_seconds: 86_400,
        lookback_window_blocks: 2_016,
        minimum_lookback_blocks: 1_008,
        parallel_lanes: 1,
        lane_model: ParallelLaneModel::SharedCommittee,
        annual_security_target: 0.0,
        annual_liveness_target: 0.0,
        roles: vec![RoleParameters {
            name: "mask".to_owned(),
            committee_size,
            certificate_threshold,
            opening_threshold,
            eligible_population: None,
        }],
        overlaps: vec![],
    }
}

#[test]
fn role_domain_separation_and_input_order_independence_hold() {
    let snapshot = snapshot(100);
    let context = context(4, 130, 10);
    let mask = select_roster(
        &snapshot,
        &context,
        CommitteeRole::Mask,
        policy(),
        schedule(),
        &bootstrap(),
    )
    .unwrap();
    let receipt = select_roster(
        &snapshot,
        &context,
        CommitteeRole::Receipt,
        policy(),
        schedule(),
        &bootstrap(),
    )
    .unwrap();
    assert_ne!(
        mask.artifact().selection_seed,
        receipt.artifact().selection_seed
    );

    let mut permuted = snapshot.clone();
    permuted.leaves.reverse();
    assert_eq!(
        EligibilitySnapshot::build(
            permuted.protocol_version,
            permuted.network_id,
            permuted.sequence,
            permuted.source_start_height,
            permuted.source_end_height,
            permuted.finalized_at_height,
            permuted.leaves,
        )
        .unwrap(),
        snapshot
    );
}

#[test]
fn eligibility_must_be_finalized_before_lookback_and_entropy() {
    let recent = snapshot(120);
    assert!(matches!(
        select_roster(
            &recent,
            &context(4, 130, 10),
            CommitteeRole::Mask,
            policy(),
            schedule(),
            &bootstrap()
        ),
        Err(CommitteeError::EligibilityNotDelayed)
    ));
    let old = snapshot(100);
    let mut invalid_entropy = context(4, 130, 10);
    invalid_entropy.entropy_start_height = 100;
    assert!(matches!(
        select_roster(
            &old,
            &invalid_entropy,
            CommitteeRole::Mask,
            policy(),
            schedule(),
            &bootstrap()
        ),
        Err(CommitteeError::InvalidEntropyWindow)
    ));
}

#[test]
fn bootstrap_transition_is_explicit_and_production_gated() {
    let snapshot = snapshot(100);
    let static_context = SelectionContext {
        epoch: 1,
        selection_anchor_height: 1,
        entropy_start_height: 0,
        delayed_hns_entropy: vec![],
        prior_threshold_beacon: [0; 32],
    };
    let static_roster = select_roster(
        &snapshot,
        &static_context,
        CommitteeRole::Mask,
        policy(),
        schedule(),
        &bootstrap(),
    )
    .unwrap();
    let hybrid = select_roster(
        &snapshot,
        &context(2, 130, 11),
        CommitteeRole::Mask,
        policy(),
        schedule(),
        &bootstrap(),
    )
    .unwrap();
    let dynamic = select_roster(
        &snapshot,
        &context(4, 130, 12),
        CommitteeRole::Mask,
        policy(),
        schedule(),
        &bootstrap(),
    )
    .unwrap();
    assert_eq!(static_roster.artifact().phase, BootstrapPhase::Static);
    assert_eq!(static_roster.artifact().eligibility_snapshot_id, [0; 32]);
    assert_eq!(static_roster.artifact().eligibility_root, [0; 32]);
    assert_eq!(hybrid.artifact().phase, BootstrapPhase::Hybrid);
    assert_eq!(dynamic.artifact().phase, BootstrapPhase::Dynamic);
    assert!(static_roster.artifact().trust_notice().contains("trusted"));
    assert!(!dynamic.artifact().production_eligible);
}

#[test]
fn early_reveal_and_double_sign_faults_remove_only_the_affected_role() {
    let member = [5; 32];
    let mut leaves = vec![EligibilityLeaf {
        operator_pubkey: member,
        finalized_work: amount(100),
        eligible_role_mask: 0b1111,
    }];
    let mut ledger = EligibilityFaultLedger::default();
    ledger
        .record(EligibilityFaultEvidence {
            member_pubkey: member,
            role: CommitteeRole::Mask,
            kind: EligibilityFaultKind::EarlyMaskReveal,
            observed_epoch: 4,
            exclusion_through_epoch: 8,
            evidence_root: [9; 32],
        })
        .unwrap();
    ledger.apply(&mut leaves, 5);
    assert!(!leaves[0].role_eligible(CommitteeRole::Mask));
    assert!(leaves[0].role_eligible(CommitteeRole::Receipt));
    assert_ne!(ledger.evidence_root(), [0; 32]);

    let mut expired = vec![EligibilityLeaf {
        operator_pubkey: member,
        finalized_work: amount(100),
        eligible_role_mask: 0b1111,
    }];
    ledger.apply(&mut expired, 9);
    assert!(expired[0].role_eligible(CommitteeRole::Mask));
}

#[test]
fn roster_recomputation_and_certificate_role_epoch_are_enforced() {
    let snapshot = snapshot(100);
    let context = context(4, 130, 10);
    let roster = select_roster(
        &snapshot,
        &context,
        CommitteeRole::Settlement,
        policy(),
        schedule(),
        &bootstrap(),
    )
    .unwrap();
    let verified = verify_roster(
        roster.artifact(),
        &snapshot,
        &context,
        CommitteeRole::Settlement,
        policy(),
        schedule(),
        &bootstrap(),
    )
    .unwrap();
    let object = OperatorRecordV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        operator_pubkey: hash(1),
        sequence: 1,
        supported_features: 0,
        payout_bucket_ids: vec![],
        contact_metadata_hash: None,
        signature_suite: 1,
        signature: SignatureBytes::empty(),
    };
    let all_keys = keys();
    let selected_keys: Vec<_> = all_keys
        .iter()
        .filter(|key| {
            verified
                .artifact()
                .members
                .contains(&key.verifying_key().to_bytes())
        })
        .take(3)
        .collect();
    let signatures = assemble_ed25519_set(
        selected_keys
            .iter()
            .map(|key| sign_certificate(key, 2, &object))
            .collect(),
    )
    .unwrap();
    verified
        .verify_certificate(CommitteeRole::Settlement, 4, &signatures, &object)
        .unwrap();
    assert!(matches!(
        verified.verify_certificate(CommitteeRole::Receipt, 4, &signatures, &object),
        Err(CommitteeError::CertificateContextMismatch)
    ));
    assert!(matches!(
        verified.verify_certificate(CommitteeRole::Settlement, 5, &signatures, &object),
        Err(CommitteeError::CertificateContextMismatch)
    ));

    let mut tampered = roster.into_artifact();
    tampered.members.swap(0, 1);
    assert!(matches!(
        verify_roster(
            &tampered,
            &snapshot,
            &context,
            CommitteeRole::Settlement,
            policy(),
            schedule(),
            &bootstrap()
        ),
        Err(CommitteeError::RosterMismatch)
    ));
}

#[test]
fn production_release_flag_is_local_and_risk_report_is_policy_bound() {
    let snapshot = snapshot(100);
    let context = context(4, 130, 10);
    let selected = select_roster(
        &snapshot,
        &context,
        CommitteeRole::Mask,
        policy(),
        schedule(),
        &bootstrap(),
    )
    .unwrap();
    let mut forged = selected.artifact().clone();
    forged.production_eligible = true;
    forged.production_risk_profile_commitment = Some([99; 32]);
    let verified = verify_roster(
        &forged,
        &snapshot,
        &context,
        CommitteeRole::Mask,
        policy(),
        schedule(),
        &bootstrap(),
    )
    .unwrap();
    assert!(!verified.artifact().production_eligible);
    assert_eq!(verified.artifact().production_risk_profile_commitment, None);

    let matching = enforce_profile(&release_risk_profile(5, 3, 4)).unwrap();
    let authorized = authorize_production(verified.clone(), &matching, true).unwrap();
    assert!(authorized.artifact().production_eligible);
    assert_eq!(
        authorized.artifact().production_risk_profile_commitment,
        Some(matching.profile_commitment())
    );

    let wrong_size = enforce_profile(&release_risk_profile(6, 4, 5)).unwrap();
    assert!(matches!(
        authorize_production(verified.clone(), &wrong_size, true),
        Err(CommitteeError::ProductionGate)
    ));
    assert!(matches!(
        authorize_production(verified, &matching, false),
        Err(CommitteeError::ProductionGate)
    ));
}

#[test]
fn frozen_root_defeats_late_censorship_and_successor_recovers() {
    let snapshot = snapshot(100);
    let first = select_roster(
        &snapshot,
        &context(4, 130, 20),
        CommitteeRole::Receipt,
        policy(),
        schedule(),
        &bootstrap(),
    )
    .unwrap();
    let unavailable: BTreeSet<_> = first.artifact().members.iter().copied().collect();

    // An incumbent can publish a different later view, but it cannot make a
    // roster bound to the frozen root verify against that censored snapshot.
    let censored = EligibilitySnapshot::build(
        CORE_V2,
        2,
        2,
        1,
        90,
        100,
        snapshot
            .leaves
            .iter()
            .filter(|leaf| !unavailable.contains(&leaf.operator_pubkey))
            .cloned()
            .collect(),
    )
    .unwrap();
    assert_ne!(snapshot.snapshot_id(), censored.snapshot_id());
    assert!(
        verify_roster(
            first.artifact(),
            &censored,
            &context(4, 130, 20),
            CommitteeRole::Receipt,
            policy(),
            schedule(),
            &bootstrap(),
        )
        .is_err()
    );

    let replacement = select_roster(
        &snapshot,
        &context(5, 131, 40),
        CommitteeRole::Receipt,
        policy(),
        schedule(),
        &bootstrap(),
    )
    .unwrap();
    let mut controller = RotationController::new(first);
    controller
        .replace_after_failure(
            LivenessFailureEvidence {
                role: CommitteeRole::Receipt,
                epoch: 4,
                missed_deadline_ms: 1_000,
                unavailable_members: unavailable,
                transcript_root: hash(80),
            },
            replacement,
        )
        .unwrap();
    assert_eq!(controller.active().artifact().epoch, 5);
    assert_eq!(controller.failures().len(), 1);
}
