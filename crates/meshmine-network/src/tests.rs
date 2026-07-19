use ed25519_dalek::SigningKey;
use meshmine_crypto::sign_object;

use super::*;

#[test]
fn protocol_topics_have_nonoverlapping_latency_lanes() {
    for topic in [
        GossipTopic::Parent,
        GossipTopic::MaskSession,
        GossipTopic::MaskOpening,
        GossipTopic::FaultProof,
    ] {
        assert_eq!(topic.protocol_lane(), ProtocolLane::FastPath);
    }
    for topic in [
        GossipTopic::Operator,
        GossipTopic::Share,
        GossipTopic::ReceiptBatch,
        GossipTopic::SessionClose,
    ] {
        assert_eq!(topic.protocol_lane(), ProtocolLane::Accounting);
    }
    assert_eq!(
        GossipTopic::BodyDescriptor.protocol_lane(),
        ProtocolLane::Availability
    );
    for topic in [GossipTopic::PayoutSnapshot, GossipTopic::PayoutPlan] {
        assert_eq!(topic.protocol_lane(), ProtocolLane::Settlement);
    }

    assert_eq!(
        RequestProtocol::SessionTranscript.protocol_lane(),
        ProtocolLane::FastPath
    );
    assert_eq!(
        RequestProtocol::ShareObject.protocol_lane(),
        ProtocolLane::Accounting
    );
    assert_eq!(
        RequestProtocol::BodyShard.protocol_lane(),
        ProtocolLane::Availability
    );
    assert_eq!(
        RequestProtocol::PayoutTranscript.protocol_lane(),
        ProtocolLane::Settlement
    );
}

#[test]
fn published_clock_profile_rejects_skew_and_inconsistent_windows() {
    let profile = ClockProfile {
        maximum_wall_clock_skew_ms: 2_000,
        maximum_assignment_window_ms: 10_000,
        maximum_submission_grace_ms: 3_000,
        maximum_receipt_finalization_ms: 5_000,
        minimum_timed_open_delay_ms: 1_000,
        maximum_timed_open_delay_ms: 10_000,
        skew_behavior: ClockSkewBehavior::PauseNewAssignments,
    };
    assert_eq!(profile.validate_peer_time(10_000, 12_000), Ok(()));
    assert_eq!(
        profile.validate_peer_time(10_000, 12_001),
        Err(NetworkError::ClockSkew)
    );
    let schedule = SessionSchedule {
        assignment_start_ms: 1_000,
        assignment_end_ms: 6_000,
        submission_end_ms: 8_000,
        receipt_boundary_ms: 11_000,
        timed_open_after_ms: 13_000,
    };
    assert_eq!(profile.validate_schedule(&schedule), Ok(()));
    assert_eq!(
        profile.validate_schedule(&SessionSchedule {
            timed_open_after_ms: 11_999,
            ..schedule
        }),
        Err(NetworkError::InvalidSchedule)
    );
}

fn hello(key: &SigningKey, economic: Option<[u8; 32]>) -> PeerHello {
    let mut hello = PeerHello {
        protocol_version: 2,
        network_id: 2,
        transport_pubkey: key.verifying_key().to_bytes(),
        economic_operator_pubkey: economic,
        challenge_nonce: [9; 32],
        signature: SignatureBytes::empty(),
    };
    hello.signature = sign_object(key, 2, &hello);
    hello
}

fn expect_new_validation(decision: IngressDecision) -> IngressToken {
    match decision {
        IngressDecision::Validate(token) => token,
        IngressDecision::AlreadyValidated => panic!("expected a new validation"),
    }
}

#[test]
fn authentication_keeps_transport_and_economic_identity_separate() {
    let (limits, topics) = default_overlay_limits();
    let mut node = OverlayNode::new(2, limits, topics);
    let key = SigningKey::from_bytes(&[1; 32]);
    let economic = [2; 32];
    node.authenticate_peer(&hello(&key, Some(economic)), 0)
        .unwrap();
    assert_eq!(
        node.peer_identities(&key.verifying_key().to_bytes()),
        Some((key.verifying_key().to_bytes(), Some(economic)))
    );
}

#[test]
fn completed_validation_is_idempotent_but_pending_validation_is_rejected() {
    let (limits, topics) = default_overlay_limits();
    let mut node = OverlayNode::new(2, limits, topics);
    let key = SigningKey::from_bytes(&[1; 32]);
    let peer = key.verifying_key().to_bytes();
    node.authenticate_peer(&hello(&key, None), 0).unwrap();
    let envelope = ObjectEnvelope {
        topic: GossipTopic::Share,
        object_id: [7; 32],
        encoded_size: 10,
        missing_parent: false,
        parent_fetch_depth: 0,
    };

    let token = expect_new_validation(
        node.begin_validation(&peer, envelope.clone(), true, 1)
            .unwrap(),
    );
    assert_eq!(
        node.begin_validation(&peer, envelope.clone(), true, 1),
        Err(NetworkError::Duplicate)
    );

    node.finish_validation(token, true).unwrap();
    assert_eq!(
        node.begin_validation(&peer, envelope.clone(), true, 1),
        Ok(IngressDecision::AlreadyValidated)
    );
    assert_eq!(
        node.begin_validation(&peer, envelope, false, 1),
        Err(NetworkError::InvalidSignature)
    );
}

#[test]
fn expired_validation_token_cannot_finish_a_replacement_peers_validation() {
    let (mut limits, topics) = default_overlay_limits();
    limits.pending_validation_timeout_ms = 10;
    let mut node = OverlayNode::new(2, limits, topics);
    let first = SigningKey::from_bytes(&[1; 32]);
    let second = SigningKey::from_bytes(&[2; 32]);
    let first_peer = first.verifying_key().to_bytes();
    let second_peer = second.verifying_key().to_bytes();
    node.authenticate_peer(&hello(&first, None), 0).unwrap();
    node.authenticate_peer(&hello(&second, None), 0).unwrap();
    let envelope = ObjectEnvelope {
        topic: GossipTopic::Share,
        object_id: [7; 32],
        encoded_size: 10,
        missing_parent: false,
        parent_fetch_depth: 0,
    };

    let expired = expect_new_validation(
        node.begin_validation(&first_peer, envelope.clone(), true, 1)
            .unwrap(),
    );
    let replacement = expect_new_validation(
        node.begin_validation(&second_peer, envelope, true, 11)
            .unwrap(),
    );
    assert_ne!(expired.generation, replacement.generation);
    assert_eq!(node.expired_validation_count(), 1);

    assert_eq!(
        node.finish_validation(expired, false),
        Err(NetworkError::UnknownValidation)
    );
    assert!(!node.events().iter().any(|event| {
        matches!(
            event,
            OverlayEvent::PeerPenalized {
                transport_pubkey,
                ..
            } if transport_pubkey == &second_peer
        )
    }));
    node.finish_validation(replacement, true).unwrap();
    assert_eq!(
        node.events().last(),
        Some(&OverlayEvent::ValidationCompleted { object_id: [7; 32] })
    );
}

#[test]
fn reconnect_cannot_reset_identity_binding_or_body_quota() {
    let (mut limits, topics) = default_overlay_limits();
    limits.body_download_bytes_per_window = 10;
    let mut node = OverlayNode::new(2, limits, topics);
    let key = SigningKey::from_bytes(&[1; 32]);
    let peer = key.verifying_key().to_bytes();
    let economic = [2; 32];
    node.authenticate_peer(&hello(&key, Some(economic)), 0)
        .unwrap();
    node.request_body_bytes(&peer, 10, 1).unwrap();
    node.authenticate_peer(&hello(&key, Some(economic)), 2)
        .unwrap();
    assert_eq!(
        node.request_body_bytes(&peer, 1, 2),
        Err(NetworkError::BodyQuota)
    );
    assert!(matches!(
        node.authenticate_peer(&hello(&key, Some([3; 32])), 3),
        Err(NetworkError::Authentication(_))
    ));
}

#[test]
fn identity_churn_evicts_idle_lru_peers_and_never_exceeds_the_peer_bound() {
    let (mut limits, topics) = default_overlay_limits();
    limits.maximum_tracked_peers = 3;
    limits.peer_inactivity_timeout_ms = 10;
    let mut node = OverlayNode::new(2, limits, topics);
    let keys: Vec<_> = (1..=10)
        .map(|byte| SigningKey::from_bytes(&[byte; 32]))
        .collect();

    for (now_ms, key) in keys[..3].iter().enumerate() {
        node.authenticate_peer(&hello(key, None), now_ms as u64)
            .unwrap();
        assert!(node.peer_count() <= limits.maximum_tracked_peers);
    }
    node.authenticate_peer(&hello(&keys[0], None), 3).unwrap();
    assert_eq!(
        node.authenticate_peer(&hello(&keys[3], None), 4),
        Err(NetworkError::PeerCapacity)
    );
    node.authenticate_peer(&hello(&keys[3], None), 12).unwrap();
    assert!(
        node.peer_identities(&keys[0].verifying_key().to_bytes())
            .is_some()
    );
    assert_eq!(
        node.peer_identities(&keys[1].verifying_key().to_bytes()),
        None
    );

    for (index, key) in keys[4..].iter().enumerate() {
        let now_ms = 22 + u64::try_from(index).unwrap() * 10;
        node.authenticate_peer(&hello(key, None), now_ms).unwrap();
        assert!(node.peer_count() <= limits.maximum_tracked_peers);
    }

    for key in &keys[..7] {
        assert_eq!(node.peer_identities(&key.verifying_key().to_bytes()), None);
    }
    for key in &keys[7..] {
        assert!(
            node.peer_identities(&key.verifying_key().to_bytes())
                .is_some()
        );
    }
    assert_eq!(node.evicted_peer_count(), 7);
}

#[test]
fn peer_admission_fails_closed_instead_of_evicting_in_flight_validation() {
    let (mut limits, topics) = default_overlay_limits();
    limits.maximum_tracked_peers = 1;
    limits.peer_inactivity_timeout_ms = 0;
    limits.pending_validation_timeout_ms = 10;
    let mut node = OverlayNode::new(2, limits, topics);
    let first = SigningKey::from_bytes(&[1; 32]);
    let second = SigningKey::from_bytes(&[2; 32]);
    let first_peer = first.verifying_key().to_bytes();
    node.authenticate_peer(&hello(&first, None), 0).unwrap();
    let token = expect_new_validation(
        node.begin_validation(
            &first_peer,
            ObjectEnvelope {
                topic: GossipTopic::Share,
                object_id: [1; 32],
                encoded_size: 10,
                missing_parent: false,
                parent_fetch_depth: 0,
            },
            true,
            1,
        )
        .unwrap(),
    );

    assert_eq!(
        node.authenticate_peer(&hello(&second, None), 2),
        Err(NetworkError::PeerCapacity)
    );
    assert_eq!(node.peer_count(), 1);
    assert!(node.peer_identities(&first_peer).is_some());
    node.authenticate_peer(&hello(&second, None), 11).unwrap();
    assert_eq!(node.peer_count(), 1);
    assert!(node.peer_identities(&first_peer).is_none());
    assert_eq!(node.expired_validation_count(), 1);
    assert_eq!(
        node.finish_validation(token, true),
        Err(NetworkError::UnknownValidation)
    );
}

#[test]
fn peer_admission_evicts_idle_state_without_orphaning_in_flight_state() {
    let (mut limits, topics) = default_overlay_limits();
    limits.maximum_tracked_peers = 2;
    limits.peer_inactivity_timeout_ms = 0;
    let mut node = OverlayNode::new(2, limits, topics);
    let first = SigningKey::from_bytes(&[1; 32]);
    let second = SigningKey::from_bytes(&[2; 32]);
    let third = SigningKey::from_bytes(&[3; 32]);
    let first_peer = first.verifying_key().to_bytes();
    let second_peer = second.verifying_key().to_bytes();
    node.authenticate_peer(&hello(&first, None), 0).unwrap();
    node.authenticate_peer(&hello(&second, None), 0).unwrap();
    let token = expect_new_validation(
        node.begin_validation(
            &first_peer,
            ObjectEnvelope {
                topic: GossipTopic::Share,
                object_id: [1; 32],
                encoded_size: 10,
                missing_parent: false,
                parent_fetch_depth: 0,
            },
            true,
            1,
        )
        .unwrap(),
    );

    node.authenticate_peer(&hello(&third, None), 2).unwrap();
    assert!(node.peer_identities(&first_peer).is_some());
    assert!(node.peer_identities(&second_peer).is_none());
    node.finish_validation(token, true).unwrap();
}

#[test]
fn retained_event_history_stays_bounded_under_sustained_volume() {
    let (mut limits, topics) = default_overlay_limits();
    limits.maximum_retained_events = 5;
    let mut node = OverlayNode::new(2, limits, topics);
    let key = SigningKey::from_bytes(&[1; 32]);
    let peer = key.verifying_key().to_bytes();
    node.authenticate_peer(&hello(&key, None), 0).unwrap();

    for byte in 1..=100 {
        let object_id = [byte; 32];
        let token = expect_new_validation(
            node.begin_validation(
                &peer,
                ObjectEnvelope {
                    topic: GossipTopic::Share,
                    object_id,
                    encoded_size: 10,
                    missing_parent: false,
                    parent_fetch_depth: 0,
                },
                true,
                1,
            )
            .unwrap(),
        );
        node.finish_validation(token, true).unwrap();
        assert!(node.events().len() <= limits.maximum_retained_events);
    }

    assert_eq!(
        node.events().last(),
        Some(&OverlayEvent::ValidationCompleted {
            object_id: [100; 32]
        })
    );
    assert!(node.dropped_event_count() > 0);
    assert_eq!(
        node.dropped_event_count() + u64::try_from(node.events().len()).unwrap(),
        201
    );

    let (mut zero_limits, zero_topics) = default_overlay_limits();
    zero_limits.maximum_retained_events = 0;
    let mut zero_event_node = OverlayNode::new(2, zero_limits, zero_topics);
    zero_event_node
        .authenticate_peer(&hello(&key, None), 0)
        .unwrap();
    assert!(zero_event_node.events().is_empty());
    assert_eq!(zero_event_node.dropped_event_count(), 1);
}

#[test]
fn zero_peer_capacity_fails_closed() {
    let (mut limits, topics) = default_overlay_limits();
    limits.maximum_tracked_peers = 0;
    let mut node = OverlayNode::new(2, limits, topics);
    let key = SigningKey::from_bytes(&[1; 32]);
    assert_eq!(
        node.authenticate_peer(&hello(&key, None), 0),
        Err(NetworkError::PeerCapacity)
    );
    assert_eq!(node.peer_count(), 0);
}

#[test]
fn signatures_sizes_pending_budgets_orphans_and_quotas_are_bounded() {
    let (mut limits, mut topics) = default_overlay_limits();
    limits.maximum_pending_objects_per_peer = 1;
    limits.maximum_orphan_shares = 1;
    limits.body_download_bytes_per_window = 100;
    topics
        .get_mut(&GossipTopic::Share)
        .unwrap()
        .maximum_object_bytes = 100;
    let mut node = OverlayNode::new(2, limits, topics);
    let key = SigningKey::from_bytes(&[1; 32]);
    let peer = key.verifying_key().to_bytes();
    node.authenticate_peer(&hello(&key, None), 0).unwrap();

    let envelope = |byte, size, missing, depth| ObjectEnvelope {
        topic: GossipTopic::Share,
        object_id: [byte; 32],
        encoded_size: size,
        missing_parent: missing,
        parent_fetch_depth: depth,
    };
    assert!(matches!(
        node.begin_validation(&peer, envelope(1, 10, false, 0), false, 1),
        Err(NetworkError::InvalidSignature)
    ));
    assert!(matches!(
        node.begin_validation(&peer, envelope(2, 101, false, 0), true, 1),
        Err(NetworkError::ObjectTooLarge)
    ));
    let token = expect_new_validation(
        node.begin_validation(&peer, envelope(3, 10, true, 2), true, 1)
            .unwrap(),
    );
    assert_eq!(node.orphan_count(), 1);
    assert!(matches!(
        node.begin_validation(&peer, envelope(4, 10, false, 0), true, 1),
        Err(NetworkError::PendingBudget)
    ));
    node.finish_validation(token, true).unwrap();
    assert!(matches!(
        node.begin_validation(&peer, envelope(5, 10, true, 33), true, 1),
        Err(NetworkError::ParentDepth)
    ));
    node.request_body_bytes(&peer, 80, 1).unwrap();
    assert_eq!(
        node.request_body_bytes(&peer, 21, 1),
        Err(NetworkError::BodyQuota)
    );
    let signature_index = node
        .events()
        .iter()
        .position(|event| matches!(event, OverlayEvent::SignatureRejected { .. }))
        .unwrap();
    let validation_index = node
        .events()
        .iter()
        .position(|event| matches!(event, OverlayEvent::ValidationStarted { .. }))
        .unwrap();
    assert!(signature_index < validation_index);
}

#[test]
fn deliberate_partition_isolated_gossip_then_heals_and_reconciles() {
    let mut network = SimulatedNetwork::default();
    for node in ["a", "b", "c", "d"] {
        network.add_node(node).unwrap();
    }
    network.connect("a", "b").unwrap();
    network.connect("b", "c").unwrap();
    network.connect("c", "d").unwrap();
    network.partition(&["a", "b"], &["c", "d"]).unwrap();
    let first = simulation_object_id("partition-left");
    let second = simulation_object_id("partition-right");
    assert_eq!(network.broadcast("a", first).unwrap(), 2);
    assert_eq!(network.broadcast("d", second).unwrap(), 2);
    assert!(!network.objects("a").unwrap().contains(&second));
    assert!(!network.objects("d").unwrap().contains(&first));
    network.heal_all();
    network.reconcile();
    for node in ["a", "b", "c", "d"] {
        assert_eq!(network.objects(node).unwrap().len(), 2);
    }
}
