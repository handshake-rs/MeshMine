use meshmine_storage::{ProtocolJournal, ProtocolRecordKind, RedbStore};
use meshmine_types::{CORE_V2, PayoutPlanV2, SignatureBytes};

use super::*;

fn secure_tempdir() -> std::io::Result<tempfile::TempDir> {
    let directory = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(directory)
}

fn hash(byte: u8) -> Hash256 {
    [byte; 32]
}

fn amount(value: u64) -> U512 {
    let mut bytes = [0; 64];
    bytes[56..].copy_from_slice(&value.to_be_bytes());
    U512(bytes)
}

fn bucket(byte: u8) -> PayoutBucketV2 {
    PayoutBucketV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        operator_pubkey: hash(byte),
        bucket_sequence: u64::from(byte),
        hns_address_version: 0,
        hns_address_hash: vec![byte; 20],
        activation_height: 0,
        retirement_height: None,
        signature: SignatureBytes(vec![byte; 64]),
    }
}

fn session(index: u8, work: &[(u8, u64)], service: &[(u8, u64)]) -> ClosedSessionCredits {
    ClosedSessionCredits {
        session_close_id: hash(100 + index),
        close_anchor_height: u32::from(index),
        work: work
            .iter()
            .map(|(bucket_id, value)| BucketCredit {
                bucket: bucket(*bucket_id),
                credit: amount(*value),
            })
            .collect(),
        service: service
            .iter()
            .map(|(bucket_id, value)| BucketCredit {
                bucket: bucket(*bucket_id),
                credit: amount(*value),
            })
            .collect(),
    }
}

fn numbered_hash(value: u64) -> Hash256 {
    let mut output = [0; 32];
    output[24..].copy_from_slice(&value.to_be_bytes());
    output
}

fn numbered_session(
    index: u64,
    work: Vec<BucketCredit>,
    service: Vec<BucketCredit>,
) -> ClosedSessionCredits {
    ClosedSessionCredits {
        session_close_id: numbered_hash(index),
        close_anchor_height: u32::try_from(index).unwrap(),
        work,
        service,
    }
}

fn credit(bucket_id: u8, value: u64) -> BucketCredit {
    BucketCredit {
        bucket: bucket(bucket_id),
        credit: amount(value),
    }
}

/// The original full-history algorithm retained here as an independent test
/// oracle. It deliberately never prunes `closed_sessions`.
struct FullHistorySnapshotAccumulator {
    network_id: u8,
    next_sequence: u64,
    previous_snapshot_id: Hash256,
    snapshot_step_work: BigUint,
    pplns_window_work: BigUint,
    settlement_committee_id: Hash256,
    closed_sessions: Vec<ClosedSessionCredits>,
    new_work_since_snapshot: BigUint,
}

impl FullHistorySnapshotAccumulator {
    fn new(snapshot_step_work: u64, pplns_window_work: u64) -> Self {
        Self {
            network_id: 2,
            next_sequence: 7,
            previous_snapshot_id: hash(90),
            snapshot_step_work: snapshot_step_work.into(),
            pplns_window_work: pplns_window_work.into(),
            settlement_committee_id: hash(91),
            closed_sessions: Vec::new(),
            new_work_since_snapshot: BigUint::zero(),
        }
    }

    fn add_closed_session(
        &mut self,
        session: ClosedSessionCredits,
    ) -> Result<Option<PayoutSnapshotV2>, SettlementError> {
        let session_work = sum_credits(&session.work);
        if session_work.is_zero() {
            return Err(SettlementError::EmptySessionWork);
        }
        self.new_work_since_snapshot += session_work;
        self.closed_sessions.push(session);
        if self.new_work_since_snapshot < self.snapshot_step_work {
            return Ok(None);
        }

        let mut selected = Vec::new();
        let mut window_work = BigUint::zero();
        for selected_session in self.closed_sessions.iter().rev() {
            selected.push(selected_session);
            window_work += sum_credits(&selected_session.work);
            if window_work >= self.pplns_window_work {
                break;
            }
        }
        selected.reverse();
        let work_buckets = aggregate_work(&selected)?;
        let service_buckets = aggregate_service(&selected)?;
        let close_ids: Vec<_> = selected
            .iter()
            .map(|selected_session| selected_session.session_close_id)
            .collect();
        let service_ids: Vec<_> = selected
            .iter()
            .filter(|selected_session| !selected_session.service.is_empty())
            .map(|selected_session| selected_session.session_close_id)
            .collect();
        let first = selected.first().unwrap();
        let last = selected.last().unwrap();
        let snapshot = PayoutSnapshotV2 {
            protocol_version: 2,
            network_id: self.network_id,
            snapshot_sequence: self.next_sequence,
            previous_snapshot_id: self.previous_snapshot_id,
            first_session_close_id: first.session_close_id,
            last_session_close_id: last.session_close_id,
            close_anchor_height: last.close_anchor_height,
            work_window_target: big_to_u512(&self.pplns_window_work)?,
            actual_work_in_window: big_to_u512(&window_work)?,
            work_buckets,
            service_buckets,
            share_set_root: merkle_root(&close_ids),
            service_set_root: merkle_root(&service_ids),
            settlement_committee_id: self.settlement_committee_id,
            signer_set: SignatureSet::empty_ed25519(),
        };
        self.previous_snapshot_id = snapshot.object_id();
        self.next_sequence += 1;
        self.new_work_since_snapshot = BigUint::zero();
        Ok(Some(snapshot))
    }
}

struct DeterministicRng(u64);

impl DeterministicRng {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn below(&mut self, exclusive_upper_bound: u64) -> u64 {
        self.next() % exclusive_upper_bound
    }
}

/// The original payment-selection algorithm retained as a differential-test
/// oracle. It deliberately rebuilds paid membership from canonical history.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct FullHistoryPlanPaymentTracker {
    eligible_sequences: BTreeSet<u64>,
    canonical_payments: Vec<(Hash256, Option<u64>)>,
}

impl FullHistoryPlanPaymentTracker {
    fn add_eligible(&mut self, sequence: u64) {
        self.eligible_sequences.insert(sequence);
    }

    fn invalidate_eligible(&mut self, sequence: u64) {
        self.eligible_sequences.remove(&sequence);
    }

    fn connect_block(
        &mut self,
        block_hash: Hash256,
        paid_plan: Option<u64>,
    ) -> Result<(), SettlementError> {
        if let Some(sequence) = paid_plan
            && Some(sequence) != self.current_payable()
        {
            return Err(SettlementError::TicketCountMismatch);
        }
        self.canonical_payments.push((block_hash, paid_plan));
        Ok(())
    }

    fn disconnect_tip(&mut self, block_hash: &Hash256) -> Result<(), SettlementError> {
        if self
            .canonical_payments
            .last()
            .is_none_or(|(hash, _)| hash != block_hash)
        {
            return Err(SettlementError::DisconnectMismatch);
        }
        self.canonical_payments.pop();
        Ok(())
    }

    fn current_payable(&self) -> Option<u64> {
        let paid: BTreeSet<_> = self
            .canonical_payments
            .iter()
            .filter_map(|(_, sequence)| *sequence)
            .collect();
        self.eligible_sequences
            .iter()
            .find(|sequence| !paid.contains(sequence))
            .copied()
    }
}

fn snapshot() -> PayoutSnapshotV2 {
    let mut accumulator =
        SnapshotAccumulator::new(2, 1, [0; 32], amount(10), amount(10), hash(9)).unwrap();
    assert!(
        accumulator
            .add_closed_session(
                session(1, &[(1, 1), (2, 3)], &[(3, 2)]),
                SignatureSet::empty_ed25519()
            )
            .unwrap()
            .is_none()
    );
    accumulator
        .add_closed_session(
            session(2, &[(1, 2), (2, 6)], &[(3, 4)]),
            SignatureSet::empty_ed25519(),
        )
        .unwrap()
        .unwrap()
}

#[test]
fn snapshots_close_only_on_complete_sessions_and_include_full_boundary() {
    let mut accumulator =
        SnapshotAccumulator::new(2, 5, [0; 32], amount(10), amount(15), hash(9)).unwrap();
    assert!(
        accumulator
            .add_closed_session(session(1, &[(1, 6)], &[]), SignatureSet::empty_ed25519())
            .unwrap()
            .is_none()
    );
    let first = accumulator
        .add_closed_session(session(2, &[(2, 6)], &[]), SignatureSet::empty_ed25519())
        .unwrap()
        .unwrap();
    assert_eq!(first.snapshot_sequence, 5);
    assert_eq!(
        BigUint::from_bytes_be(&first.actual_work_in_window.0),
        12u8.into()
    );
    assert_eq!(first.first_session_close_id, hash(101));
    assert_eq!(first.last_session_close_id, hash(102));

    assert!(
        accumulator
            .add_closed_session(session(3, &[(1, 6)], &[]), SignatureSet::empty_ed25519())
            .unwrap()
            .is_none()
    );
    let second = accumulator
        .add_closed_session(session(4, &[(2, 6)], &[]), SignatureSet::empty_ed25519())
        .unwrap()
        .unwrap();
    assert_eq!(second.snapshot_sequence, 6);
    // Sessions 2, 3, and 4 are included whole: 18 > the 15 target.
    assert_eq!(
        BigUint::from_bytes_be(&second.actual_work_in_window.0),
        18u8.into()
    );
    assert_eq!(second.first_session_close_id, hash(102));
    assert_eq!(second.last_session_close_id, hash(104));
}

#[test]
fn accumulator_prunes_only_the_dead_oldest_prefix_at_exact_boundaries() {
    let limits = SnapshotAccumulatorLimits {
        max_retained_sessions: 8,
        max_retained_bucket_credits: 16,
        max_retained_payload_bytes: 64 * 1024,
    };
    let mut accumulator = SnapshotAccumulator::new_with_limits(
        2,
        1,
        [0; 32],
        amount(1_000),
        amount(10),
        hash(9),
        limits,
    )
    .unwrap();

    for (index, work) in [(1, 4), (2, 6)] {
        assert!(
            accumulator
                .add_closed_session(
                    numbered_session(index, vec![credit(1, work)], vec![]),
                    SignatureSet::empty_ed25519(),
                )
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(accumulator.stats().retained_sessions, 2);

    // Removing session 1 leaves exactly the ten-work target. Equality is a
    // complete boundary, so that oldest session can never appear again.
    accumulator
        .add_closed_session(
            numbered_session(3, vec![credit(1, 4)], vec![]),
            SignatureSet::empty_ed25519(),
        )
        .unwrap();
    assert_eq!(accumulator.stats().retained_sessions, 2);
    assert_eq!(
        accumulator
            .closed_sessions
            .iter()
            .map(|session| session.session_close_id)
            .collect::<Vec<_>>(),
        vec![numbered_hash(2), numbered_hash(3)]
    );

    // A single session larger than the window supersedes the entire older
    // prefix, but remains as the whole-session boundary for later small work.
    accumulator
        .add_closed_session(
            numbered_session(4, vec![credit(2, 11)], vec![]),
            SignatureSet::empty_ed25519(),
        )
        .unwrap();
    assert_eq!(accumulator.stats().retained_sessions, 1);
    assert_eq!(
        accumulator
            .closed_sessions
            .front()
            .unwrap()
            .session_close_id,
        numbered_hash(4)
    );
    accumulator
        .add_closed_session(
            numbered_session(5, vec![credit(3, 1)], vec![]),
            SignatureSet::empty_ed25519(),
        )
        .unwrap();
    assert_eq!(accumulator.stats().retained_sessions, 2);
    assert_eq!(
        accumulator
            .closed_sessions
            .front()
            .unwrap()
            .session_close_id,
        numbered_hash(4)
    );
}

#[test]
fn pruned_accumulator_matches_full_history_across_randomized_sequences() {
    for (scenario, (step, window)) in [(1, 1), (7, 15), (23, 9), (50, 50)].into_iter().enumerate() {
        let mut rng = DeterministicRng(0x9e37_79b9_7f4a_7c15 ^ scenario as u64);
        let mut reference = FullHistorySnapshotAccumulator::new(step, window);
        let mut pruned = SnapshotAccumulator::new_with_limits(
            2,
            7,
            hash(90),
            amount(step),
            amount(window),
            hash(91),
            SnapshotAccumulatorLimits {
                max_retained_sessions: 1_024,
                max_retained_bucket_credits: 16_384,
                max_retained_payload_bytes: 16 * 1024 * 1024,
            },
        )
        .unwrap();

        for index in 1..=1_000 {
            let work_count = 1 + rng.below(3);
            let service_count = rng.below(3);
            let work = (0..work_count)
                .map(|_| {
                    credit(
                        1 + u8::try_from(rng.below(5)).unwrap(),
                        1 + rng.below(window.saturating_mul(2).saturating_add(3)),
                    )
                })
                .collect();
            let service = (0..service_count)
                .map(|_| credit(1 + u8::try_from(rng.below(5)).unwrap(), 1 + rng.below(20)))
                .collect();
            let closed = numbered_session(index, work, service);
            let expected = reference.add_closed_session(closed.clone()).unwrap();
            let actual = pruned
                .add_closed_session(closed, SignatureSet::empty_ed25519())
                .unwrap();
            assert_eq!(actual, expected, "scenario {scenario}, session {index}");

            // This is the minimal-suffix invariant: if the oldest retained
            // session were removed, the remainder would be below the window.
            if let Some(oldest) = pruned.closed_sessions.front() {
                assert!(
                    &pruned.retained_work - sum_credits(&oldest.work) < pruned.pplns_window_work
                );
            }
            assert!(pruned.stats().retained_sessions <= pruned.limits().max_retained_sessions);

            // Exercise restart from only the checkpointable pruned state; no
            // discarded historical session is supplied to the restored copy.
            if index % 37 == 0 {
                let limits = pruned.limits();
                pruned = SnapshotAccumulator::from_checkpoint(pruned.checkpoint().unwrap(), limits)
                    .unwrap();
            }
        }
    }
}

#[test]
fn accumulator_limits_fail_closed_after_considering_safe_pruning() {
    let limits = SnapshotAccumulatorLimits {
        max_retained_sessions: 2,
        max_retained_bucket_credits: 4,
        max_retained_payload_bytes: 64 * 1024,
    };
    let mut accumulator = SnapshotAccumulator::new_with_limits(
        2,
        1,
        [0; 32],
        amount(1_000),
        amount(100),
        hash(9),
        limits,
    )
    .unwrap();
    for index in 1..=2 {
        accumulator
            .add_closed_session(
                numbered_session(index, vec![credit(1, 1)], vec![]),
                SignatureSet::empty_ed25519(),
            )
            .unwrap();
    }
    let before = accumulator.checkpoint().unwrap();
    assert_eq!(
        accumulator.add_closed_session(
            numbered_session(3, vec![credit(1, 1)], vec![]),
            SignatureSet::empty_ed25519(),
        ),
        Err(SettlementError::RetainedSessionLimit)
    );
    assert_eq!(accumulator.checkpoint().unwrap(), before);

    // The bound is evaluated after semantic pruning. A new session that alone
    // fills the window may replace all retained history even at a one-session
    // limit.
    let mut replacement = SnapshotAccumulator::new_with_limits(
        2,
        1,
        [0; 32],
        amount(1_000),
        amount(10),
        hash(9),
        SnapshotAccumulatorLimits {
            max_retained_sessions: 1,
            ..limits
        },
    )
    .unwrap();
    replacement
        .add_closed_session(
            numbered_session(1, vec![credit(1, 1)], vec![]),
            SignatureSet::empty_ed25519(),
        )
        .unwrap();
    replacement
        .add_closed_session(
            numbered_session(2, vec![credit(1, 10)], vec![]),
            SignatureSet::empty_ed25519(),
        )
        .unwrap();
    assert_eq!(replacement.stats().retained_sessions, 1);
    assert_eq!(
        replacement
            .closed_sessions
            .front()
            .unwrap()
            .session_close_id,
        numbered_hash(2)
    );

    let oversized = numbered_session(9, vec![credit(1, 1), credit(2, 1)], vec![]);
    let mut bucket_limited = SnapshotAccumulator::new_with_limits(
        2,
        1,
        [0; 32],
        amount(1_000),
        amount(100),
        hash(9),
        SnapshotAccumulatorLimits {
            max_retained_bucket_credits: 1,
            ..limits
        },
    )
    .unwrap();
    assert_eq!(
        bucket_limited.add_closed_session(oversized, SignatureSet::empty_ed25519()),
        Err(SettlementError::RetainedBucketCreditLimit)
    );

    let byte_heavy = numbered_session(10, vec![credit(1, 1)], vec![]);
    let byte_limit = session_payload_bytes(&byte_heavy).unwrap() - 1;
    let mut byte_limited = SnapshotAccumulator::new_with_limits(
        2,
        1,
        [0; 32],
        amount(1_000),
        amount(100),
        hash(9),
        SnapshotAccumulatorLimits {
            max_retained_payload_bytes: byte_limit,
            ..limits
        },
    )
    .unwrap();
    assert_eq!(
        byte_limited.add_closed_session(byte_heavy, SignatureSet::empty_ed25519()),
        Err(SettlementError::RetainedPayloadByteLimit)
    );
}

#[test]
fn accumulator_checkpoint_restores_limits_and_rejects_inconsistent_progress() {
    let limits = SnapshotAccumulatorLimits {
        max_retained_sessions: 8,
        max_retained_bucket_credits: 8,
        max_retained_payload_bytes: 64 * 1024,
    };
    let mut accumulator =
        SnapshotAccumulator::new_with_limits(2, 5, hash(8), amount(10), amount(6), hash(9), limits)
            .unwrap();
    accumulator
        .add_closed_session(
            numbered_session(1, vec![credit(1, 4)], vec![credit(2, 3)]),
            SignatureSet::empty_ed25519(),
        )
        .unwrap();
    let checkpoint = accumulator.checkpoint().unwrap();
    let restored = SnapshotAccumulator::from_checkpoint(checkpoint.clone(), limits).unwrap();
    assert_eq!(restored.checkpoint().unwrap(), checkpoint);

    let mut invalid = checkpoint;
    invalid.new_work_since_snapshot = amount(10);
    assert_eq!(
        SnapshotAccumulator::from_checkpoint(invalid, limits).unwrap_err(),
        SettlementError::InvalidAccumulatorCheckpoint
    );

    assert_eq!(
        SnapshotAccumulator::new_with_limits(
            2,
            1,
            [0; 32],
            amount(1),
            amount(1),
            hash(9),
            SnapshotAccumulatorLimits {
                max_retained_sessions: 0,
                ..limits
            },
        )
        .unwrap_err(),
        SettlementError::ZeroAccumulatorLimit
    );
}

#[test]
fn delayed_entropy_and_ticket_selection_are_deterministic() {
    let snapshot = snapshot();
    let profile = PayoutProfile {
        work_ticket_count: 64,
        service_ticket_count: 8,
        service_basis_points: 400,
        maximum_service_basis_points: 600,
        minimum_ticket_value: 1,
        maximum_coinbase_outputs: 128,
    };
    assert_eq!(
        build_payout_plan(
            &snapshot,
            snapshot.close_anchor_height,
            vec![hash(1)],
            hash(2),
            profile,
            SignatureSet::empty_ed25519()
        ),
        Err(SettlementError::EntropyNotDelayed)
    );
    let first = build_payout_plan(
        &snapshot,
        snapshot.close_anchor_height + 3,
        vec![hash(1), hash(2), hash(3)],
        hash(4),
        profile,
        SignatureSet::empty_ed25519(),
    )
    .unwrap();
    let second = build_payout_plan(
        &snapshot,
        snapshot.close_anchor_height + 3,
        vec![hash(1), hash(2), hash(3)],
        hash(4),
        profile,
        SignatureSet::empty_ed25519(),
    )
    .unwrap();
    assert_eq!(first, second);
    assert_eq!(first.work_winners.len(), 64);
    assert_eq!(first.service_winners.len(), 8);
    verify_payout_plan(&snapshot, &first, profile).unwrap();
    let mut tampered = first.clone();
    tampered.work_winners[0] = hash(99);
    assert_eq!(
        verify_payout_plan(&snapshot, &tampered, profile),
        Err(SettlementError::PlanVerificationMismatch)
    );
}

#[test]
fn monte_carlo_ticket_means_track_exact_work_proportions() {
    let snapshot = snapshot();
    let profile = PayoutProfile {
        work_ticket_count: 1,
        service_ticket_count: 0,
        service_basis_points: 0,
        maximum_service_basis_points: 600,
        minimum_ticket_value: 1,
        maximum_coinbase_outputs: 128,
    };
    // Snapshot leaves are sorted by their hash-derived bucket IDs, so identify
    // the 3-work bucket explicitly instead of relying on its vector position.
    let first_bucket = bucket(1).object_id();
    let mut first_wins = 0u64;
    let rounds = 20_000u64;
    for round in 0..rounds {
        let mut entropy = [0; 32];
        entropy[24..].copy_from_slice(&round.to_be_bytes());
        let plan = build_payout_plan(
            &snapshot,
            snapshot.close_anchor_height + 1,
            vec![entropy],
            hash(7),
            profile,
            SignatureSet::empty_ed25519(),
        )
        .unwrap();
        first_wins += u64::from(plan.work_winners[0] == first_bucket);
    }
    // Aggregated work is 3:9, so bucket one should receive 25% in expectation.
    let difference = first_wins.abs_diff(rounds / 4);
    assert!(difference < rounds / 50, "wins={first_wins}");
}

#[test]
fn rejection_boundary_has_no_modulo_bias_in_exhaustive_small_domain() {
    for weight in 1u32..=15 {
        let space = 16u32;
        let limit = (space / weight) * weight;
        let mut counts = vec![0u32; weight as usize];
        for candidate in 0..space {
            if candidate < limit {
                counts[(candidate % weight) as usize] += 1;
            }
        }
        assert!(counts.windows(2).all(|pair| pair[0] == pair[1]));
    }
}

#[test]
fn payout_values_sum_exactly_and_duplicates_combine_without_moving_mandatory_outputs() {
    let snapshot = snapshot();
    let first = snapshot.work_buckets[0].bucket_id;
    let second = snapshot.work_buckets[1].bucket_id;
    let service = snapshot.service_buckets[0].bucket_id;
    let plan = PayoutPlanV2 {
        protocol_version: 2,
        network_id: 2,
        plan_sequence: snapshot.snapshot_sequence,
        snapshot_id: snapshot.object_id(),
        entropy_anchor_start: snapshot.close_anchor_height + 1,
        entropy_anchor_count: 1,
        entropy_hashes: vec![hash(1)],
        prior_beacon: hash(2),
        plan_seed: hash(3),
        work_ticket_count: 3,
        service_ticket_count: 2,
        work_winners: vec![first, first, second],
        service_winners: vec![service, service],
        selection_transcript_hash: hash(4),
        signer_set: SignatureSet::empty_ed25519(),
    };
    let profile = PayoutProfile {
        work_ticket_count: 3,
        service_ticket_count: 2,
        service_basis_points: 500,
        maximum_service_basis_points: 600,
        minimum_ticket_value: 1,
        maximum_coinbase_outputs: 128,
    };
    let mandatory = vec![PayoutOutput {
        hns_address_version: 0,
        hns_address_hash: vec![99; 20],
        value: 500,
    }];
    let payout = build_coinbase_payouts(
        &snapshot,
        &plan,
        1_001,
        17,
        mandatory.clone(),
        Some((0, vec![88; 20])),
        profile,
    )
    .unwrap();
    let ordered = payout.skeleton.ordered_outputs().unwrap();
    assert_eq!(ordered[1], &mandatory[0]);
    assert_eq!(payout.work_pool, 951);
    assert_eq!(payout.service_pool, 50);
    assert_eq!(payout.skeleton.first_work_or_fallback.value, 634);
    let miner_total: u64 = ordered
        .iter()
        .filter(|output| output.hns_address_hash != vec![99; 20])
        .map(|output| output.value)
        .sum();
    assert_eq!(miner_total, 1_001 + 17);
    assert_eq!(
        ordered.iter().map(|output| output.value).sum::<u64>(),
        1_518
    );
}

#[test]
fn canonical_plan_payment_rolls_back_on_reorg_and_non_mesh_blocks_do_not_advance() {
    let mut tracker = PlanPaymentTracker::default();
    tracker.add_eligible(1);
    tracker.add_eligible(2);
    assert_eq!(tracker.current_payable(), Some(1));
    tracker.connect_block(hash(1), None).unwrap();
    assert_eq!(tracker.current_payable(), Some(1));
    tracker.connect_block(hash(2), Some(1)).unwrap();
    assert_eq!(tracker.current_payable(), Some(2));
    tracker.disconnect_tip(&hash(2)).unwrap();
    assert_eq!(tracker.current_payable(), Some(1));
}

#[test]
fn paid_plan_stays_paid_when_invalidated_and_readded_until_its_block_disconnects() {
    let mut tracker = PlanPaymentTracker::default();
    tracker.add_eligible(10);
    tracker.add_eligible(20);
    tracker.connect_block(hash(1), Some(10)).unwrap();

    tracker.invalidate_eligible(10);
    assert_eq!(tracker.current_payable(), Some(20));
    tracker.add_eligible(10);
    assert_eq!(tracker.current_payable(), Some(20));

    tracker.connect_block(hash(2), None).unwrap();
    tracker.invalidate_eligible(20);
    assert_eq!(tracker.current_payable(), None);
    tracker.disconnect_tip(&hash(2)).unwrap();
    assert_eq!(tracker.current_payable(), None);
    tracker.disconnect_tip(&hash(1)).unwrap();
    assert_eq!(tracker.current_payable(), Some(10));
}

#[test]
fn rejected_plan_payment_updates_are_atomic() {
    let mut tracker = PlanPaymentTracker::default();
    tracker.add_eligible(1);

    let before_wrong_plan = tracker.clone();
    assert_eq!(
        tracker.connect_block(hash(1), Some(2)).unwrap_err(),
        SettlementError::TicketCountMismatch
    );
    assert_eq!(tracker, before_wrong_plan);

    tracker.connect_block(hash(1), Some(1)).unwrap();
    let before_duplicate_payment = tracker.clone();
    assert_eq!(
        tracker.connect_block(hash(2), Some(1)).unwrap_err(),
        SettlementError::TicketCountMismatch
    );
    assert_eq!(tracker, before_duplicate_payment);

    let before_wrong_disconnect = tracker.clone();
    assert_eq!(
        tracker.disconnect_tip(&hash(9)).unwrap_err(),
        SettlementError::DisconnectMismatch
    );
    assert_eq!(tracker, before_wrong_disconnect);
}

#[test]
fn indexed_plan_payment_tracker_matches_full_history_reference() {
    for scenario in 0..16_u64 {
        let mut rng = DeterministicRng(0xd1b5_4a32_d192_ed03 ^ scenario);
        let mut reference = FullHistoryPlanPaymentTracker::default();
        let mut indexed = PlanPaymentTracker::default();

        for step in 0..2_000_u64 {
            let sequence = rng.below(64);
            let block_hash = numbered_hash((scenario << 32) | step.saturating_add(1));
            let reference_before = reference.clone();
            let indexed_before = indexed.clone();

            let (expected, actual) = match rng.below(7) {
                0 => {
                    reference.add_eligible(sequence);
                    indexed.add_eligible(sequence);
                    (Ok(()), Ok(()))
                }
                1 => {
                    reference.invalidate_eligible(sequence);
                    indexed.invalidate_eligible(sequence);
                    (Ok(()), Ok(()))
                }
                2 => (
                    reference.connect_block(block_hash, None),
                    indexed.connect_block(block_hash, None),
                ),
                3 => {
                    let paid_plan = reference.current_payable();
                    (
                        reference.connect_block(block_hash, paid_plan),
                        indexed.connect_block(block_hash, paid_plan),
                    )
                }
                4 => {
                    let current = reference.current_payable();
                    let invalid_sequence = if current == Some(sequence) {
                        (sequence + 1) % 64
                    } else {
                        sequence
                    };
                    (
                        reference.connect_block(block_hash, Some(invalid_sequence)),
                        indexed.connect_block(block_hash, Some(invalid_sequence)),
                    )
                }
                5 => {
                    let disconnect_hash = reference
                        .canonical_payments
                        .last()
                        .map_or(block_hash, |(hash, _)| *hash);
                    (
                        reference.disconnect_tip(&disconnect_hash),
                        indexed.disconnect_tip(&disconnect_hash),
                    )
                }
                _ => {
                    let wrong_hash = numbered_hash(u64::MAX - step);
                    (
                        reference.disconnect_tip(&wrong_hash),
                        indexed.disconnect_tip(&wrong_hash),
                    )
                }
            };

            assert_eq!(actual, expected, "scenario {scenario}, step {step}");
            if actual.is_err() {
                assert_eq!(reference, reference_before);
                assert_eq!(indexed, indexed_before);
            }
            assert_eq!(
                indexed.current_payable(),
                reference.current_payable(),
                "scenario {scenario}, step {step}"
            );
            assert_eq!(
                indexed.eligible_sequences, reference.eligible_sequences,
                "scenario {scenario}, step {step}"
            );
            assert_eq!(
                indexed.canonical_payments, reference.canonical_payments,
                "scenario {scenario}, step {step}"
            );

            let paid: BTreeSet<_> = reference
                .canonical_payments
                .iter()
                .filter_map(|(_, paid_plan)| *paid_plan)
                .collect();
            let payable: BTreeSet<_> = reference
                .eligible_sequences
                .difference(&paid)
                .copied()
                .collect();
            assert_eq!(indexed.paid_sequences, paid);
            assert_eq!(indexed.payable_sequences, payable);
        }
    }
}

#[test]
fn entropy_window_reorg_invalidates_plan_until_recomputed() {
    let snapshot = snapshot();
    let profile = PayoutProfile {
        work_ticket_count: 1,
        service_ticket_count: 0,
        service_basis_points: 0,
        maximum_service_basis_points: 600,
        minimum_ticket_value: 1,
        maximum_coinbase_outputs: 8,
    };
    let plan = build_payout_plan(
        &snapshot,
        100,
        vec![hash(10), hash(11), hash(12)],
        hash(13),
        profile,
        SignatureSet::empty_ed25519(),
    )
    .unwrap();
    let plan_id = plan.object_id();
    let mut entropy = EntropyPlanTracker::default();
    entropy.register(&plan).unwrap();
    let mut payments = PlanPaymentTracker::default();
    payments.add_eligible(plan.plan_sequence);
    assert!(entropy.is_canonical(&plan_id));
    let invalidated = entropy.disconnect_entropy_block(101, hash(11));
    assert_eq!(invalidated, BTreeSet::from([plan.plan_sequence]));
    for sequence in invalidated {
        payments.invalidate_eligible(sequence);
    }
    assert!(!entropy.is_canonical(&plan_id));
    assert_eq!(payments.current_payable(), None);

    // A caller that has revalidated the exact immutable plan after HNS returns
    // to the same branch may reactivate it without manufacturing a replacement
    // object ID.
    entropy.register(&plan).unwrap();
    payments.add_eligible(plan.plan_sequence);
    assert!(entropy.is_canonical(&plan_id));
    assert_eq!(payments.current_payable(), Some(plan.plan_sequence));
}

#[test]
fn canonical_overlay_reorg_invalidates_parents_closes_sessions_and_rolls_back_payment() {
    let snapshot = snapshot();
    let profile = PayoutProfile {
        work_ticket_count: 1,
        service_ticket_count: 0,
        service_basis_points: 0,
        maximum_service_basis_points: 600,
        minimum_ticket_value: 1,
        maximum_coinbase_outputs: 8,
    };
    let plan = build_payout_plan(
        &snapshot,
        11,
        vec![hash(11)],
        hash(13),
        profile,
        SignatureSet::empty_ed25519(),
    )
    .unwrap();
    let mut entropy = EntropyPlanTracker::default();
    entropy.register(&plan).unwrap();
    let mut payments = PlanPaymentTracker::default();
    payments.add_eligible(plan.plan_sequence);
    let mut view = CanonicalOverlayView::default();
    view.connect_block(10, hash(10), None, &mut payments)
        .unwrap();
    view.connect_block(11, hash(11), Some(plan.plan_sequence), &mut payments)
        .unwrap();

    let parent = meshmine_types::SessionParentCertificateV2 {
        protocol_version: 2,
        network_id: 2,
        parent_hash: hash(10),
        parent_height: 10,
        parent_chainwork: meshmine_types::U256(hash(12)),
        observed_ntime: 1,
        certificate_sequence: 1,
        previous_parent_certificate_id: [0; 32],
        signer_set: SignatureSet::empty_ed25519(),
    };
    view.register_parent_certificate(&parent).unwrap();
    let session = meshmine_types::MaskSessionV2 {
        protocol_version: 2,
        network_id: 2,
        lane_id: 0,
        session_sequence: 1,
        parent_certificate_id: parent.object_id(),
        parent_hash: parent.parent_hash,
        hns_network_target: meshmine_types::U256(hash(1)),
        capture_target: meshmine_types::U256(hash(2)),
        accounting_target: meshmine_types::U256(hash(2)),
        leading_zero_prefix_q: 8,
        blind_band_bits_d: 8,
        mask_hash: hash(3),
        mask_commitment_root: hash(4),
        mask_committee_id: hash(5),
        fast_eval_policy: 0,
        assignment_start_ms: 1,
        assignment_end_ms: 2,
        submission_end_ms: 3,
        timed_open_after_ms: 4,
        previous_session_id: [0; 32],
        signer_set: SignatureSet::empty_ed25519(),
    };
    view.register_session(&session).unwrap();

    let first = view
        .disconnect_tip(11, hash(11), &mut payments, &mut entropy)
        .unwrap();
    assert_eq!(
        first.invalidated_plan_sequences,
        BTreeSet::from([plan.plan_sequence])
    );
    assert!(first.invalidated_parent_certificates.is_empty());
    assert_eq!(payments.current_payable(), None);

    let second = view
        .disconnect_tip(10, hash(10), &mut payments, &mut entropy)
        .unwrap();
    assert_eq!(
        second.invalidated_parent_certificates,
        BTreeSet::from([parent.object_id()])
    );
    assert_eq!(
        second.closed_sessions,
        BTreeSet::from([session.object_id()])
    );
    assert!(second.retain_share_and_body_evidence);
    assert!(second.recompute_current_payable_plan);
    assert!(!view.is_parent_canonical(&parent.object_id()));
    assert!(view.session_closed_for_reorg(&session.object_id()));
}

#[test]
fn service_credits_are_capped_per_event_and_role_and_cannot_replay() {
    let policy = ServiceCreditPolicy {
        maximum_per_event: BTreeMap::from([(ServiceRole::MaskOpening, amount(5))]),
        maximum_per_role_per_snapshot: BTreeMap::from([(ServiceRole::MaskOpening, amount(8))]),
    };
    let mut ledger = ServiceCreditLedger::default();
    let make_event = |subject_id, credit| ServiceCreditEvent {
        protocol_version: 2,
        network_id: 2,
        role: ServiceRole::MaskOpening,
        subject_id,
        beneficiary_bucket_id: bucket(1).object_id(),
        observed_height: 10,
        credit,
    };
    ledger
        .certify(&policy, make_event(hash(1), amount(5)), bucket(1))
        .unwrap();
    assert_eq!(
        ledger.certify(&policy, make_event(hash(1), amount(1)), bucket(1)),
        Err(SettlementError::DuplicateServiceEvent)
    );
    assert_eq!(
        ledger.certify(&policy, make_event(hash(2), amount(4)), bucket(1)),
        Err(SettlementError::ServiceRoleCap)
    );
    assert_eq!(ledger.into_credits().len(), 1);
}

#[test]
fn halving_economics_and_output_policy_force_profile_adaptation() {
    let snapshot = snapshot();
    let mut profile = PayoutProfile {
        work_ticket_count: 64,
        service_ticket_count: 8,
        service_basis_points: 400,
        maximum_service_basis_points: 600,
        minimum_ticket_value: 10,
        maximum_coinbase_outputs: 128,
    };
    let plan = build_payout_plan(
        &snapshot,
        snapshot.close_anchor_height + 1,
        vec![hash(1)],
        hash(2),
        profile,
        SignatureSet::empty_ed25519(),
    )
    .unwrap();
    assert_eq!(
        build_coinbase_payouts(&snapshot, &plan, 100, 0, vec![], None, profile),
        Err(SettlementError::UneconomicTicket)
    );
    profile.minimum_ticket_value = 0;
    profile.maximum_coinbase_outputs = 1;
    assert_eq!(
        build_coinbase_payouts(&snapshot, &plan, 100, 0, vec![], None, profile),
        Err(SettlementError::CoinbaseOutputPolicy)
    );
}

#[test]
fn bootstrap_transition_is_explicit_and_cannot_silently_persist() {
    let policy = BootstrapPayoutPolicy {
        final_bootstrap_height: 99,
        first_normal_height: 100,
        first_normal_session_close_id: hash(7),
        bootstrap_allocation_commitment: hash(8),
    };
    assert_eq!(
        policy.payout_mode(99, None),
        Ok(PayoutMode::Bootstrap {
            allocation_commitment: hash(8)
        })
    );
    assert_eq!(
        policy.payout_mode(100, None),
        Err(SettlementError::NormalSnapshotUnavailable)
    );
    assert_eq!(
        policy.payout_mode(100, Some(hash(7))),
        Ok(PayoutMode::Normal)
    );
}

#[test]
fn snapshots_and_plans_are_persisted_before_becoming_visible() {
    let directory = secure_tempdir().unwrap();
    let path = directory.path().join("settlement.redb");
    let snapshot_id;
    let plan_id;
    {
        let store = RedbStore::create(&path).unwrap();
        let journal = ProtocolJournal::new(&store);
        let mut accumulator =
            SnapshotAccumulator::new(2, 1, [0; 32], amount(1), amount(1), hash(9)).unwrap();
        let snapshot = accumulator
            .add_closed_session_durable(
                session(1, &[(1, 1)], &[(2, 1)]),
                SignatureSet::empty_ed25519(),
                &journal,
            )
            .unwrap()
            .unwrap();
        snapshot_id = snapshot.object_id();
        let profile = PayoutProfile {
            work_ticket_count: 1,
            service_ticket_count: 1,
            service_basis_points: 100,
            maximum_service_basis_points: 600,
            minimum_ticket_value: 1,
            maximum_coinbase_outputs: 8,
        };
        let plan = build_payout_plan_durable(
            &snapshot,
            snapshot.close_anchor_height + 1,
            vec![hash(3)],
            hash(4),
            profile,
            SignatureSet::empty_ed25519(),
            &journal,
        )
        .unwrap();
        plan_id = plan.object_id();
    }
    let store = RedbStore::create(&path).unwrap();
    let journal = ProtocolJournal::new(&store);
    assert!(
        journal
            .load(ProtocolRecordKind::PayoutSnapshot, &snapshot_id)
            .unwrap()
            .is_some()
    );
    assert!(
        journal
            .load(ProtocolRecordKind::PayoutPlan, &plan_id)
            .unwrap()
            .is_some()
    );
}
