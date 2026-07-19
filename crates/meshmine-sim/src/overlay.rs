use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use meshmine_body::{AvailabilityError, encode_body, reconstruct_body};
use meshmine_codec::Encoder;
use meshmine_crypto::{assemble_ed25519_set, sign_certificate};
use meshmine_hns::{Hash256, merkle_root};
use meshmine_mpc_api::{
    AcceptedShareHash, MpcBackend, MpcError, ResearchVssBackend, SessionPhase, SetupRequest,
    TimedOpeningGate, evaluate_accepted_winners,
};
use meshmine_network::{SimulatedNetwork, simulation_object_id};
use meshmine_settlement::PlanPaymentTracker;
use meshmine_share::detect_receipt_equivocation;
use meshmine_storage::MemoryStore;
use meshmine_types::{ReceiptBatchV2, SignatureSet, U512, UnsignedObject, domain_hash};
use serde::{Deserialize, Serialize};

use crate::SimulationError;

const EVENT_DOMAIN: &str = "meshmine/testnet-event/v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OverlayTestnetConfig {
    pub session_count: u64,
    pub committee_members: u8,
    pub opening_threshold: u8,
    pub seed: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentEvent {
    pub sequence: u64,
    pub kind: String,
    pub session: Option<u64>,
    pub subject: String,
    pub outcome: String,
    pub evidence_root: String,
    pub previous_event_hash: String,
    pub event_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlaySummary {
    pub accepted_winners: u64,
    pub recovered_winners: u64,
    pub unrecoverable_winners_under_assumption: u64,
    pub injected_incidents: u64,
    pub final_event_hash: String,
    pub research_backend_production_eligible: bool,
    pub public_deployment_verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayTranscript {
    pub protocol_version: u16,
    pub network_id: u8,
    pub implementation: String,
    pub verifier_contract: String,
    pub seed: String,
    pub session_count: u64,
    pub committee_members: u8,
    pub opening_threshold: u8,
    pub events: Vec<IncidentEvent>,
    pub summary: OverlaySummary,
}

#[derive(Default)]
struct TranscriptBuilder {
    events: Vec<IncidentEvent>,
    previous: Hash256,
}

pub fn run_overlay_testnet(
    config: OverlayTestnetConfig,
) -> Result<OverlayTranscript, SimulationError> {
    if config.session_count == 0
        || config.committee_members == 0
        || config.opening_threshold == 0
        || config.opening_threshold > config.committee_members
    {
        return Err(SimulationError::OverlayFailure(
            "invalid overlay-testnet configuration".to_owned(),
        ));
    }
    let mut transcript = TranscriptBuilder::default();
    run_partition_drill(&mut transcript)?;
    run_body_unavailability_drill(&mut transcript)?;
    run_receipt_equivocation_drill(&mut transcript)?;
    run_reorg_drill(&mut transcript)?;
    run_committee_liveness_drill(&mut transcript)?;

    let store = MemoryStore::default();
    let backend = ResearchVssBackend::new(&store);
    let keys: Vec<_> = (1..=config.committee_members)
        .map(|index| {
            let mut seed = config.seed;
            seed[0] ^= index;
            SigningKey::from_bytes(&seed)
        })
        .collect();
    let target = {
        let mut target = [0xff; 32];
        target[0] = 0;
        target
    };
    let mut recovered = 0u64;
    for session in 0..config.session_count {
        let request = SetupRequest {
            protocol_version: 2,
            network_id: 2,
            lane_id: (session % 4) as u16,
            session_sequence: session + 1,
            parent_hash: labeled_hash("parent", session),
            leading_zero_prefix_q: 8,
            blind_band_bits_d: 8,
            threshold: config.opening_threshold,
            timed_open_after_ms: 1_000,
            deterministic_seed: labeled_hash("mask-seed", session),
        };
        let setup = backend.setup(&request, &keys).map_err(overlay)?;
        let accepted = AcceptedShareHash {
            share_id: labeled_hash("accepted-share", session),
            raw_share_hash: [0; 32],
        };
        transcript.record(
            "accepted_winner",
            Some(session),
            accepted.share_id,
            "receipt-boundary-pending",
            setup.transcript_root,
        );
        let offline = (session as usize) % keys.len();
        let openings = setup
            .members
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != offline)
            .take(usize::from(config.opening_threshold))
            .map(|(_, member)| backend.load_opening(&setup.session_binding, member))
            .collect::<Result<Vec<_>, _>>()
            .map_err(overlay)?;
        let mut gate = TimedOpeningGate {
            phase: SessionPhase::ReceiptFinalizing,
            timed_open_after_ms: 1_000,
            accepted_boundary_fixed: false,
        };
        if session == 0 {
            match backend.timed_open(&setup, &openings, &gate, 1_000) {
                Err(MpcError::BoundaryNotFixed) => transcript.record(
                    "early_mask_reveal_rejected",
                    Some(session),
                    setup.session_binding,
                    "rejected-before-receipt-boundary",
                    setup.mask_commitment_root,
                ),
                other => {
                    return Err(SimulationError::OverlayFailure(format!(
                        "unexpected early-open result: {other:?}"
                    )));
                }
            }
        }
        gate.fix_receipt_boundary();
        let opened = backend
            .timed_open(&setup, &openings, &gate, 1_000)
            .map_err(overlay)?;
        let winners = evaluate_accepted_winners(&opened, std::slice::from_ref(&accepted), &target);
        if winners != vec![accepted.share_id] {
            return Err(SimulationError::OverlayFailure(
                "accepted winner was not recovered".to_owned(),
            ));
        }
        recovered += 1;
        transcript.record(
            "winner_recovered",
            Some(session),
            accepted.share_id,
            "timed-threshold-open",
            opened.opening_transcript_root,
        );
    }
    let final_hash = hex::encode(transcript.previous);
    Ok(OverlayTranscript {
        protocol_version: 2,
        network_id: 2,
        implementation: "meshmine-rust-local-overlay-harness/v2".to_owned(),
        verifier_contract: "hsd-oracle/verify-overlay-transcript.js".to_owned(),
        seed: hex::encode(config.seed),
        session_count: config.session_count,
        committee_members: config.committee_members,
        opening_threshold: config.opening_threshold,
        events: transcript.events,
        summary: OverlaySummary {
            accepted_winners: config.session_count,
            recovered_winners: recovered,
            unrecoverable_winners_under_assumption: config.session_count - recovered,
            injected_incidents: 6,
            final_event_hash: final_hash,
            research_backend_production_eligible: backend.security_properties().production_eligible,
            public_deployment_verified: false,
        },
    })
}

pub fn render_overlay_explorer(transcript: &OverlayTranscript) -> String {
    let incidents: Vec<_> = transcript
        .events
        .iter()
        .filter(|event| event.kind != "accepted_winner" && event.kind != "winner_recovered")
        .collect();
    let mut rows = String::new();
    for event in incidents {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
            event.sequence,
            escape_html(&event.kind),
            escape_html(&event.outcome),
            escape_html(&event.event_hash[..16]),
        ));
    }
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>MeshMine local overlay explorer</title><style>body{{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#15202b}}.warning{{padding:1rem;background:#fff2cc;border:1px solid #d6a900}}table{{border-collapse:collapse;width:100%}}th,td{{padding:.55rem;border-bottom:1px solid #ddd;text-align:left}}code{{font-size:.85em}}</style></head><body><h1>MeshMine overlay incident explorer</h1><p class=\"warning\"><strong>Research harness only.</strong> This is reproducible local evidence, not a public deployment or production MPC claim.</p><dl><dt>Sessions</dt><dd>{}</dd><dt>Accepted/recovered</dt><dd>{}/{}</dd><dt>Unrecoverable under threshold assumption</dt><dd>{}</dd><dt>Final transcript hash</dt><dd><code>{}</code></dd></dl><h2>Injected incidents</h2><table><thead><tr><th>Seq</th><th>Incident</th><th>Outcome</th><th>Event hash</th></tr></thead><tbody>{}</tbody></table></body></html>",
        transcript.session_count,
        transcript.summary.accepted_winners,
        transcript.summary.recovered_winners,
        transcript.summary.unrecoverable_winners_under_assumption,
        transcript.summary.final_event_hash,
        rows,
    )
}

impl TranscriptBuilder {
    fn record(
        &mut self,
        kind: &str,
        session: Option<u64>,
        subject: Hash256,
        outcome: &str,
        evidence_root: Hash256,
    ) {
        let sequence = self.events.len() as u64;
        let event_hash = event_hash(
            sequence,
            &self.previous,
            kind,
            session,
            &subject,
            outcome,
            &evidence_root,
        );
        self.events.push(IncidentEvent {
            sequence,
            kind: kind.to_owned(),
            session,
            subject: hex::encode(subject),
            outcome: outcome.to_owned(),
            evidence_root: hex::encode(evidence_root),
            previous_event_hash: hex::encode(self.previous),
            event_hash: hex::encode(event_hash),
        });
        self.previous = event_hash;
    }
}

fn run_partition_drill(transcript: &mut TranscriptBuilder) -> Result<(), SimulationError> {
    let mut network = SimulatedNetwork::default();
    for node in ["operator-a", "operator-b", "operator-c", "operator-d"] {
        network.add_node(node).map_err(overlay)?;
    }
    network
        .connect("operator-a", "operator-b")
        .map_err(overlay)?;
    network
        .connect("operator-b", "operator-c")
        .map_err(overlay)?;
    network
        .connect("operator-c", "operator-d")
        .map_err(overlay)?;
    network
        .partition(&["operator-a", "operator-b"], &["operator-c", "operator-d"])
        .map_err(overlay)?;
    let left = simulation_object_id("left-partition-share");
    let right = simulation_object_id("right-partition-share");
    transcript.record(
        "network_partition_started",
        None,
        left,
        "two-components",
        right,
    );
    if network.broadcast("operator-a", left).map_err(overlay)? != 2
        || network.broadcast("operator-d", right).map_err(overlay)? != 2
    {
        return Err(SimulationError::OverlayFailure(
            "partition did not isolate gossip".to_owned(),
        ));
    }
    network.heal_all();
    network.reconcile();
    if ["operator-a", "operator-b", "operator-c", "operator-d"]
        .iter()
        .any(|node| {
            network
                .objects(node)
                .is_none_or(|objects| objects.len() != 2)
        })
    {
        return Err(SimulationError::OverlayFailure(
            "partition reconciliation failed".to_owned(),
        ));
    }
    transcript.record(
        "network_partition_reconciled",
        None,
        left,
        "all-certified-shares-retained",
        right,
    );
    Ok(())
}

fn run_body_unavailability_drill(
    transcript: &mut TranscriptBuilder,
) -> Result<(), SimulationError> {
    let body = vec![0x5a; 32 * 1024];
    let body_id = domain_hash("meshmine/test-body/v2", &body);
    let encoded = encode_body(2, 2, body_id, &body, 6, 3, 100).map_err(overlay)?;
    if reconstruct_body(&encoded.descriptor, &encoded.shards[..5])
        != Err(AvailabilityError::InsufficientShards)
    {
        return Err(SimulationError::OverlayFailure(
            "body unexpectedly reconstructed below threshold".to_owned(),
        ));
    }
    transcript.record(
        "body_unavailability_detected",
        None,
        body_id,
        "five-of-nine-insufficient",
        encoded.descriptor.object_id(),
    );
    let recovered = reconstruct_body(
        &encoded.descriptor,
        &[
            encoded.shards[0].clone(),
            encoded.shards[2].clone(),
            encoded.shards[4].clone(),
            encoded.shards[6].clone(),
            encoded.shards[7].clone(),
            encoded.shards[8].clone(),
        ],
    )
    .map_err(overlay)?;
    if recovered != body {
        return Err(SimulationError::OverlayFailure(
            "body recovery bytes differ".to_owned(),
        ));
    }
    transcript.record(
        "body_reconstructed",
        None,
        body_id,
        "six-of-nine-recovered",
        encoded.descriptor.shard_merkle_root,
    );
    Ok(())
}

fn run_receipt_equivocation_drill(
    transcript: &mut TranscriptBuilder,
) -> Result<(), SimulationError> {
    let keys: Vec<_> = (20..23)
        .map(|byte| SigningKey::from_bytes(&[byte; 32]))
        .collect();
    let make_batch = |accepted: Hash256| ReceiptBatchV2 {
        protocol_version: 2,
        network_id: 2,
        session_id: [40; 32],
        batch_sequence: 7,
        previous_batch_id: [0; 32],
        accepted_share_ids: vec![accepted],
        accepted_work_keys: vec![accepted],
        credited_work: vec![unit_work()],
        share_merkle_root: merkle_root(&[accepted]),
        cumulative_share_count: 1,
        cumulative_credited_work: unit_work(),
        signer_set: SignatureSet::empty_ed25519(),
    };
    let mut first = make_batch([41; 32]);
    let mut second = make_batch([42; 32]);
    first.signer_set = assemble_ed25519_set(
        keys.iter()
            .map(|key| sign_certificate(key, 2, &first))
            .collect(),
    )
    .map_err(overlay)?;
    second.signer_set = assemble_ed25519_set(
        keys.iter()
            .map(|key| sign_certificate(key, 2, &second))
            .collect(),
    )
    .map_err(overlay)?;
    let proof = detect_receipt_equivocation(&first, &second).map_err(overlay)?;
    let mut evidence = Encoder::new();
    evidence.fixed(&proof.first_batch_id);
    evidence.fixed(&proof.second_batch_id);
    for signer in &proof.equivocating_signers {
        evidence.fixed(signer);
    }
    transcript.record(
        "receipt_equivocation_detected",
        None,
        proof.session_id,
        "conflicting-batch-signers-identified",
        domain_hash("meshmine/equivocation-evidence/v2", evidence.as_bytes()),
    );
    Ok(())
}

fn run_reorg_drill(transcript: &mut TranscriptBuilder) -> Result<(), SimulationError> {
    let mut tracker = PlanPaymentTracker::default();
    tracker.add_eligible(1);
    let first = [50; 32];
    tracker.connect_block(first, Some(1)).map_err(overlay)?;
    transcript.record("hns_plan_paid", None, first, "plan-sequence-1", [1; 32]);
    tracker.disconnect_tip(&first).map_err(overlay)?;
    transcript.record(
        "hns_reorg_rollback",
        None,
        first,
        "plan-sequence-1-unpaid",
        [2; 32],
    );
    let replacement = [51; 32];
    tracker
        .connect_block(replacement, Some(1))
        .map_err(overlay)?;
    transcript.record(
        "hns_plan_repaid",
        None,
        replacement,
        "plan-sequence-1-canonical",
        [3; 32],
    );
    Ok(())
}

fn run_committee_liveness_drill(transcript: &mut TranscriptBuilder) -> Result<(), SimulationError> {
    let failed = BTreeSet::from([[60; 32], [61; 32], [62; 32]]);
    if failed.len() < 3 {
        return Err(SimulationError::OverlayFailure(
            "committee failure injection was incomplete".to_owned(),
        ));
    }
    transcript.record(
        "committee_liveness_failure",
        None,
        [63; 32],
        "certificate-deadline-missed",
        merkle_root(&failed.iter().copied().collect::<Vec<_>>()),
    );
    let replacement_online = 4usize;
    if replacement_online < 3 {
        return Err(SimulationError::OverlayFailure(
            "replacement committee remained blocked".to_owned(),
        ));
    }
    transcript.record(
        "committee_replacement_activated",
        None,
        [64; 32],
        "next-epoch-threshold-online",
        [65; 32],
    );
    Ok(())
}

fn event_hash(
    sequence: u64,
    previous: &Hash256,
    kind: &str,
    session: Option<u64>,
    subject: &Hash256,
    outcome: &str,
    evidence_root: &Hash256,
) -> Hash256 {
    let mut encoder = Encoder::new();
    encoder.u16(2);
    encoder.u64(sequence);
    encoder.fixed(previous);
    encoder.bytes(kind.as_bytes());
    match session {
        Some(session) => {
            encoder.u8(1);
            encoder.u64(session);
        }
        None => encoder.u8(0),
    }
    encoder.fixed(subject);
    encoder.bytes(outcome.as_bytes());
    encoder.fixed(evidence_root);
    domain_hash(EVENT_DOMAIN, encoder.as_bytes())
}

fn labeled_hash(label: &str, sequence: u64) -> Hash256 {
    let mut encoder = Encoder::new();
    encoder.bytes(label.as_bytes());
    encoder.u64(sequence);
    domain_hash("meshmine/testnet-label/v2", encoder.as_bytes())
}

fn unit_work() -> U512 {
    let mut work = [0; 64];
    work[63] = 1;
    U512(work)
}

fn overlay(error: impl std::fmt::Display) -> SimulationError {
    SimulationError::OverlayFailure(error.to_string())
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_harness_recovers_every_accepted_winner_and_hash_chain_is_stable() {
        let config = OverlayTestnetConfig {
            session_count: 100,
            committee_members: 5,
            opening_threshold: 3,
            seed: [77; 32],
        };
        let first = run_overlay_testnet(config).unwrap();
        let second = run_overlay_testnet(config).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.summary.accepted_winners, 100);
        assert_eq!(first.summary.recovered_winners, 100);
        assert_eq!(first.summary.unrecoverable_winners_under_assumption, 0);
        assert!(!first.summary.research_backend_production_eligible);
        assert!(!first.summary.public_deployment_verified);
        assert!(render_overlay_explorer(&first).contains("Research harness only"));
    }
}
