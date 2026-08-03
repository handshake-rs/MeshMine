//! Versioned MPC boundary and test-only timed VSS opening backend.
//!
//! The test backend uses a transient trusted setup coordinator to create
//! constrained mask material, then distributes Shamir shares. Committee
//! members receive only their own share. This is suitable for staged regtest
//! fault testing, not a production malicious-secure MPC claim.

pub mod distributed;
pub mod mask_hash_circuit;

use std::collections::HashSet;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use meshmine_codec::{CodecError, DecodeLimits, Decoder, Encoder};
use meshmine_hns::{Hash256, blake2b_256, merkle_root};
use meshmine_storage::{DurableStore, StorageError};
use meshmine_types::{SignatureBytes, domain_hash};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use thiserror::Error;

const MATERIAL_NAMESPACE: &str = "mask-opening-v2";
const SESSION_RESERVATION_NAMESPACE: &str = "mask-session-reservation-v2";
const RETIRED_SESSION_NAMESPACE: &str = "mask-session-retired-v2";
const PUBLIC_TRANSCRIPT_NAMESPACE: &str = "mask-public-transcript-v2";
const SHARE_COMMITMENT_DOMAIN: &str = "meshmine/opening-share-commitment/v2";
const SHARE_SIGNATURE_DOMAIN: &str = "meshmine/mask-opening-share/v2";
const SESSION_BINDING_DOMAIN: &str = "meshmine/mask-vss-session/v2";
const TRANSCRIPT_DOMAIN: &str = "meshmine/mask-vss-transcript/v2";
const VSS_RNG_DOMAIN: &str = "meshmine/mask-vss-rng/v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendSecurityProperties {
    pub malicious_secure: bool,
    pub guaranteed_output_delivery: bool,
    pub identifiable_abort: bool,
    pub trusted_setup_coordinator: bool,
    pub production_eligible: bool,
}

#[derive(Clone, Debug)]
pub struct SetupRequest {
    pub protocol_version: u16,
    pub network_id: u8,
    pub lane_id: u16,
    pub session_sequence: u64,
    pub parent_hash: Hash256,
    pub leading_zero_prefix_q: u16,
    pub blind_band_bits_d: u16,
    pub threshold: u8,
    pub timed_open_after_ms: u64,
    pub deterministic_seed: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VssSetup {
    pub session_binding: Hash256,
    pub parent_hash: Hash256,
    pub mask_hash: Hash256,
    pub mask_commitment_root: Hash256,
    pub transcript_root: Hash256,
    pub leading_zero_prefix_q: u16,
    pub blind_band_bits_d: u16,
    pub threshold: u8,
    pub timed_open_after_ms: u64,
    pub members: Vec<[u8; 32]>,
    pub share_commitments: Vec<Hash256>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpeningShare {
    pub session_binding: Hash256,
    pub member_pubkey: [u8; 32],
    pub x: u8,
    pub values: [u8; 32],
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedMask {
    pub mask: Hash256,
    pub opening_transcript_root: Hash256,
    pub valid_opening_members: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedShareHash {
    pub share_id: Hash256,
    pub raw_share_hash: Hash256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimestampedAcceptedShare {
    pub share: AcceptedShareHash,
    pub accepted_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EarlyRevealOutcome {
    pub first_observed_ms: u64,
    pub revealing_member: [u8; 32],
    pub eligible_share_ids: Vec<Hash256>,
    pub ineligible_share_ids: Vec<Hash256>,
    pub winner_share_ids: Vec<Hash256>,
    pub assignments_stopped: bool,
    pub mask_permanently_retired: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WinnerTriggeredCloseOutcome {
    pub winning_share_id: Hash256,
    pub deterministic_cutoff_ms: u64,
    pub eligible_share_ids: Vec<Hash256>,
    pub ineligible_share_ids: Vec<Hash256>,
    pub opened: OpenedMask,
    pub assignments_stopped: bool,
    pub submissions_stopped_after_cutoff: bool,
    pub block_reconstruction_required: bool,
    pub session_restart_required: bool,
    pub mask_permanently_retired: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FastEvalOutcome {
    Losing {
        winner: bool,
        transcript_root: Hash256,
    },
    Winner {
        winner: bool,
        opened: OpenedMask,
    },
    Aborted {
        transcript_root: Hash256,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionPhase {
    MaskCommitted,
    Assigning,
    SubmissionGrace,
    ReceiptFinalizing,
    Opening,
    Opened,
    Closed,
    Aborted,
    TimedRecovery,
    FailedThreshold,
}

#[derive(Clone, Debug)]
pub struct TimedOpeningGate {
    pub phase: SessionPhase,
    pub timed_open_after_ms: u64,
    pub accepted_boundary_fixed: bool,
}

#[derive(Debug, Error)]
pub enum MpcError {
    #[error("committee size must be 1..=255 and threshold must be in range")]
    InvalidThreshold,
    #[error("invalid mask prefix or blind-band parameters")]
    InvalidMaskParameters,
    #[error("duplicate committee public key")]
    DuplicateMember,
    #[error("opening attempted before its configured time")]
    OpeningTooEarly,
    #[error("accepted-share boundary is not fixed")]
    BoundaryNotFixed,
    #[error("opening share has invalid session/member binding")]
    InvalidOpeningBinding,
    #[error("opening share commitment mismatch")]
    InvalidOpeningCommitment,
    #[error("opening share signature is invalid")]
    InvalidOpeningSignature,
    #[error("fewer than threshold valid opening shares")]
    InsufficientOpeningShares,
    #[error("reconstructed mask does not match maskHash")]
    MaskHashMismatch,
    #[error("reconstructed mask violates session constraints")]
    MaskConstraintViolation,
    #[error("opening material is missing after restart")]
    MissingOpeningMaterial,
    #[error("logical lane/session sequence was already bound to another mask session")]
    SessionReuse,
    #[error("mask session was permanently retired and cannot be set up again")]
    SessionRetired,
    #[error("opening material key was already bound to different bytes")]
    OpeningMaterialConflict,
    #[error("winner-triggered close requires a verified fast-path winner")]
    FastOutcomeNotWinner,
    #[error("fast-path winning share was not accepted by the deterministic cutoff")]
    WinnerShareNotEligible,
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Codec(#[from] CodecError),
}

pub trait MpcBackend {
    fn security_properties(&self) -> BackendSecurityProperties;

    fn setup(&self, request: &SetupRequest, members: &[SigningKey]) -> Result<VssSetup, MpcError>;

    fn timed_open(
        &self,
        setup: &VssSetup,
        opening_shares: &[OpeningShare],
        gate: &TimedOpeningGate,
        now_ms: u64,
    ) -> Result<OpenedMask, MpcError>;

    fn fast_evaluate(
        &self,
        setup: &VssSetup,
        private_opening_material: &[OpeningShare],
        raw_share_hash: &Hash256,
        network_target: &Hash256,
        force_abort: bool,
    ) -> Result<FastEvalOutcome, MpcError>;
}

pub struct DeterministicVssBackend<'a> {
    store: &'a dyn DurableStore,
}

impl<'a> DeterministicVssBackend<'a> {
    pub fn new(store: &'a dyn DurableStore) -> Self {
        Self { store }
    }

    pub fn load_opening(
        &self,
        session_binding: &Hash256,
        member_pubkey: &[u8; 32],
    ) -> Result<OpeningShare, MpcError> {
        let key = material_key(session_binding, member_pubkey);
        let bytes = self
            .store
            .get(MATERIAL_NAMESPACE, &key)?
            .ok_or(MpcError::MissingOpeningMaterial)?;
        decode_opening_share(&bytes)
    }

    pub fn erase_opening(
        &self,
        session_binding: &Hash256,
        member_pubkey: &[u8; 32],
    ) -> Result<(), MpcError> {
        self.store.delete(
            MATERIAL_NAMESPACE,
            &material_key(session_binding, member_pubkey),
        )?;
        Ok(())
    }

    /// Persist public post-open evidence and a permanent tombstone before
    /// erasing every live opening share. Restarts and restored post-retirement
    /// backups retain the tombstone and cannot regenerate this session.
    pub fn retire_after_audit(
        &self,
        setup: &VssSetup,
        opened: &OpenedMask,
    ) -> Result<(), MpcError> {
        if blake2b_256(&[&setup.parent_hash, &opened.mask]) != setup.mask_hash {
            return Err(MpcError::MaskHashMismatch);
        }
        if !mask_constraints_valid(
            &opened.mask,
            setup.leading_zero_prefix_q,
            setup.blind_band_bits_d,
        ) {
            return Err(MpcError::MaskConstraintViolation);
        }
        let key = hex::encode(setup.session_binding);
        let mut public = Encoder::new();
        public.fixed(&opened.mask);
        public.fixed(&setup.mask_hash);
        public.fixed(&setup.transcript_root);
        public.fixed(&opened.opening_transcript_root);
        let public = public.into_bytes();
        if !self
            .store
            .put_if_absent(PUBLIC_TRANSCRIPT_NAMESPACE, &key, &public)?
            && self
                .store
                .get(PUBLIC_TRANSCRIPT_NAMESPACE, &key)?
                .as_deref()
                != Some(public.as_slice())
        {
            return Err(MpcError::OpeningMaterialConflict);
        }
        self.store
            .put_if_absent(RETIRED_SESSION_NAMESPACE, &key, &setup.session_binding)?;
        for member in &setup.members {
            self.erase_opening(&setup.session_binding, member)?;
        }
        Ok(())
    }

    pub fn public_retirement_transcript(
        &self,
        session_binding: &Hash256,
    ) -> Result<Option<Vec<u8>>, MpcError> {
        Ok(self
            .store
            .get(PUBLIC_TRANSCRIPT_NAMESPACE, &hex::encode(session_binding))?)
    }

    pub fn handle_and_retire_early_reveal(
        &self,
        setup: &VssSetup,
        revealed_mask: Hash256,
        revealing_member: [u8; 32],
        first_observed_ms: u64,
        accepted: &[TimestampedAcceptedShare],
        network_target: &Hash256,
    ) -> Result<EarlyRevealOutcome, MpcError> {
        let outcome = handle_early_reveal(
            setup,
            revealed_mask,
            revealing_member,
            first_observed_ms,
            accepted,
            network_target,
        )?;
        let mut transcript = Encoder::new();
        transcript.fixed(&setup.session_binding);
        transcript.fixed(&revealing_member);
        transcript.u64(first_observed_ms);
        self.retire_after_audit(
            setup,
            &OpenedMask {
                mask: revealed_mask,
                opening_transcript_root: domain_hash(
                    "meshmine/early-mask-reveal/v2",
                    transcript.as_bytes(),
                ),
                valid_opening_members: vec![revealing_member],
            },
        )?;
        Ok(outcome)
    }

    /// Convert a verified fast-path winner into the deterministic close
    /// boundary required by section 10.10. Body reconstruction/submission and
    /// construction of the threshold SessionCloseV2 remain caller duties, but
    /// this operation stops the accepted set at `released_at_ms`, validates the
    /// winner against the opened mask, publishes the mask transcript, and
    /// permanently tombstones the session before returning.
    pub fn handle_and_retire_fast_winner(
        &self,
        setup: &VssSetup,
        outcome: FastEvalOutcome,
        winning_share_id: Hash256,
        released_at_ms: u64,
        accepted: &[TimestampedAcceptedShare],
        network_target: &Hash256,
    ) -> Result<WinnerTriggeredCloseOutcome, MpcError> {
        let FastEvalOutcome::Winner {
            winner: true,
            opened,
        } = outcome
        else {
            return Err(MpcError::FastOutcomeNotWinner);
        };
        let winner = accepted
            .iter()
            .find(|accepted| {
                accepted.share.share_id == winning_share_id
                    && accepted.accepted_at_ms <= released_at_ms
            })
            .ok_or(MpcError::WinnerShareNotEligible)?;
        let mut pow = [0; 32];
        for (index, byte) in pow.iter_mut().enumerate() {
            *byte = winner.share.raw_share_hash[index] ^ opened.mask[index];
        }
        if pow > *network_target {
            return Err(MpcError::FastOutcomeNotWinner);
        }
        let mut eligible_share_ids = Vec::new();
        let mut ineligible_share_ids = Vec::new();
        for accepted in accepted {
            if accepted.accepted_at_ms <= released_at_ms {
                eligible_share_ids.push(accepted.share.share_id);
            } else {
                ineligible_share_ids.push(accepted.share.share_id);
            }
        }
        self.retire_after_audit(setup, &opened)?;
        Ok(WinnerTriggeredCloseOutcome {
            winning_share_id,
            deterministic_cutoff_ms: released_at_ms,
            eligible_share_ids,
            ineligible_share_ids,
            opened,
            assignments_stopped: true,
            submissions_stopped_after_cutoff: true,
            block_reconstruction_required: true,
            session_restart_required: true,
            mask_permanently_retired: true,
        })
    }
}

impl MpcBackend for DeterministicVssBackend<'_> {
    fn security_properties(&self) -> BackendSecurityProperties {
        BackendSecurityProperties {
            malicious_secure: false,
            guaranteed_output_delivery: false,
            identifiable_abort: true,
            trusted_setup_coordinator: true,
            production_eligible: false,
        }
    }

    fn setup(&self, request: &SetupRequest, members: &[SigningKey]) -> Result<VssSetup, MpcError> {
        validate_request(request, members)?;
        let reservation_key = logical_session_key(request);
        if let Some(binding) = self
            .store
            .get(SESSION_RESERVATION_NAMESPACE, &reservation_key)?
            && self
                .store
                .get(RETIRED_SESSION_NAMESPACE, &hex::encode(binding))?
                .is_some()
        {
            return Err(MpcError::SessionRetired);
        }
        let mut ordered: Vec<_> = members.iter().collect();
        ordered.sort_by_key(|key| key.verifying_key().to_bytes());
        let ordered_pubkeys: Vec<_> = ordered
            .iter()
            .map(|key| key.verifying_key().to_bytes())
            .collect();

        let mut rng = ChaCha20Rng::from_seed(vss_rng_seed(request));
        let mask = generate_constrained_mask(
            &mut rng,
            request.leading_zero_prefix_q,
            request.blind_band_bits_d,
        );
        let mask_hash = blake2b_256(&[&request.parent_hash, &mask]);
        let session_binding = session_binding(request, &mask_hash, &ordered_pubkeys);
        let shares = shamir_split(&mask, request.threshold, ordered.len() as u8, &mut rng);

        let mut opening_shares = Vec::with_capacity(ordered.len());
        let mut commitments = Vec::with_capacity(ordered.len());
        for (index, signing_key) in ordered.iter().enumerate() {
            let member_pubkey = signing_key.verifying_key().to_bytes();
            let x = index as u8 + 1;
            let values = shares[index];
            let commitment = opening_commitment(&session_binding, &member_pubkey, x, &values);
            commitments.push(commitment);
            let signature = signing_key.sign(&opening_message(
                &session_binding,
                &member_pubkey,
                x,
                &values,
            ));
            opening_shares.push(OpeningShare {
                session_binding,
                member_pubkey,
                x,
                values,
                signature: SignatureBytes(signature.to_bytes().to_vec()),
            });
        }
        let mask_commitment_root = merkle_root(&commitments);
        let transcript_root = setup_transcript_root(
            &session_binding,
            &mask_hash,
            &mask_commitment_root,
            &ordered_pubkeys,
        );

        if !self.store.put_if_absent(
            SESSION_RESERVATION_NAMESPACE,
            &reservation_key,
            &session_binding,
        )? && self
            .store
            .get(SESSION_RESERVATION_NAMESPACE, &reservation_key)?
            .as_deref()
            != Some(session_binding.as_slice())
        {
            return Err(MpcError::SessionReuse);
        }

        // Durability precedes publication of the setup result.
        for share in &opening_shares {
            let key = material_key(&share.session_binding, &share.member_pubkey);
            let encoded = encode_opening_share(share);
            if !self
                .store
                .put_if_absent(MATERIAL_NAMESPACE, &key, &encoded)?
                && self.store.get(MATERIAL_NAMESPACE, &key)?.as_deref() != Some(encoded.as_slice())
            {
                return Err(MpcError::OpeningMaterialConflict);
            }
        }

        Ok(VssSetup {
            session_binding,
            parent_hash: request.parent_hash,
            mask_hash,
            mask_commitment_root,
            transcript_root,
            leading_zero_prefix_q: request.leading_zero_prefix_q,
            blind_band_bits_d: request.blind_band_bits_d,
            threshold: request.threshold,
            timed_open_after_ms: request.timed_open_after_ms,
            members: ordered_pubkeys,
            share_commitments: commitments,
        })
    }

    fn timed_open(
        &self,
        setup: &VssSetup,
        opening_shares: &[OpeningShare],
        gate: &TimedOpeningGate,
        now_ms: u64,
    ) -> Result<OpenedMask, MpcError> {
        if !gate.accepted_boundary_fixed {
            return Err(MpcError::BoundaryNotFixed);
        }
        if now_ms < gate.timed_open_after_ms || now_ms < setup.timed_open_after_ms {
            return Err(MpcError::OpeningTooEarly);
        }
        if merkle_root(&setup.share_commitments) != setup.mask_commitment_root {
            return Err(MpcError::InvalidOpeningCommitment);
        }

        let mut valid = Vec::new();
        let mut seen_x = HashSet::new();
        for share in opening_shares {
            let Some(member_index) = setup
                .members
                .iter()
                .position(|member| member == &share.member_pubkey)
            else {
                return Err(MpcError::InvalidOpeningBinding);
            };
            if share.session_binding != setup.session_binding
                || share.x as usize != member_index + 1
                || !seen_x.insert(share.x)
            {
                return Err(MpcError::InvalidOpeningBinding);
            }
            let commitment = opening_commitment(
                &share.session_binding,
                &share.member_pubkey,
                share.x,
                &share.values,
            );
            if commitment != setup.share_commitments[member_index] {
                return Err(MpcError::InvalidOpeningCommitment);
            }
            verify_opening_signature(share)?;
            valid.push(share.clone());
        }
        if valid.len() < usize::from(setup.threshold) {
            return Err(MpcError::InsufficientOpeningShares);
        }
        valid.sort_by_key(|share| share.x);
        let mask = shamir_reconstruct(&valid[..usize::from(setup.threshold)]);
        if !mask_constraints_valid(&mask, setup.leading_zero_prefix_q, setup.blind_band_bits_d) {
            return Err(MpcError::MaskConstraintViolation);
        }
        if blake2b_256(&[&setup.parent_hash, &mask]) != setup.mask_hash {
            return Err(MpcError::MaskHashMismatch);
        }

        let opening_hashes: Vec<_> = valid
            .iter()
            .map(|share| {
                opening_commitment(
                    &share.session_binding,
                    &share.member_pubkey,
                    share.x,
                    &share.values,
                )
            })
            .collect();
        Ok(OpenedMask {
            mask,
            opening_transcript_root: merkle_root(&opening_hashes),
            valid_opening_members: valid.iter().map(|share| share.member_pubkey).collect(),
        })
    }

    fn fast_evaluate(
        &self,
        setup: &VssSetup,
        private_opening_material: &[OpeningShare],
        raw_share_hash: &Hash256,
        network_target: &Hash256,
        force_abort: bool,
    ) -> Result<FastEvalOutcome, MpcError> {
        let transcript_root = fast_eval_transcript(setup, raw_share_hash);
        if force_abort {
            return Ok(FastEvalOutcome::Aborted { transcript_root });
        }
        let opened = reconstruct_verified(setup, private_opening_material)?;
        let mut pow = [0; 32];
        for (index, byte) in pow.iter_mut().enumerate() {
            *byte = raw_share_hash[index] ^ opened.mask[index];
        }
        if pow <= *network_target {
            Ok(FastEvalOutcome::Winner {
                winner: true,
                opened,
            })
        } else {
            // The mask and PoW value are deliberately dropped from the public
            // losing result.
            Ok(FastEvalOutcome::Losing {
                winner: false,
                transcript_root,
            })
        }
    }
}

impl TimedOpeningGate {
    pub fn fix_receipt_boundary(&mut self) {
        self.accepted_boundary_fixed = true;
        self.phase = SessionPhase::Opening;
    }

    pub fn abort_with_accepted_shares(&mut self) {
        self.phase = SessionPhase::TimedRecovery;
    }
}

pub fn evaluate_accepted_winners(
    opened: &OpenedMask,
    accepted: &[AcceptedShareHash],
    network_target: &Hash256,
) -> Vec<Hash256> {
    accepted
        .iter()
        .filter_map(|share| {
            let mut pow = [0; 32];
            for (index, byte) in pow.iter_mut().enumerate() {
                *byte = share.raw_share_hash[index] ^ opened.mask[index];
            }
            (pow <= *network_target).then_some(share.share_id)
        })
        .collect()
}

/// Handle a verifiable public mask disclosure before the authorized boundary.
/// The first observation is the deterministic cutoff: earlier accepted shares
/// remain eligible and are evaluated immediately; later observations receive
/// no credit. Eligibility exclusion of `revealing_member` is committed by the
/// committee fault ledger.
pub fn handle_early_reveal(
    setup: &VssSetup,
    revealed_mask: Hash256,
    revealing_member: [u8; 32],
    first_observed_ms: u64,
    accepted: &[TimestampedAcceptedShare],
    network_target: &Hash256,
) -> Result<EarlyRevealOutcome, MpcError> {
    if !setup.members.contains(&revealing_member) {
        return Err(MpcError::InvalidOpeningBinding);
    }
    if blake2b_256(&[&setup.parent_hash, &revealed_mask]) != setup.mask_hash {
        return Err(MpcError::MaskHashMismatch);
    }
    if !mask_constraints_valid(
        &revealed_mask,
        setup.leading_zero_prefix_q,
        setup.blind_band_bits_d,
    ) {
        return Err(MpcError::MaskConstraintViolation);
    }
    let mut eligible = Vec::new();
    let mut ineligible = Vec::new();
    let mut winners = Vec::new();
    for accepted in accepted {
        if accepted.accepted_at_ms <= first_observed_ms {
            eligible.push(accepted.share.share_id);
            let mut pow = [0; 32];
            for (index, byte) in pow.iter_mut().enumerate() {
                *byte = accepted.share.raw_share_hash[index] ^ revealed_mask[index];
            }
            if pow <= *network_target {
                winners.push(accepted.share.share_id);
            }
        } else {
            ineligible.push(accepted.share.share_id);
        }
    }
    Ok(EarlyRevealOutcome {
        first_observed_ms,
        revealing_member,
        eligible_share_ids: eligible,
        ineligible_share_ids: ineligible,
        winner_share_ids: winners,
        assignments_stopped: true,
        mask_permanently_retired: true,
    })
}

fn validate_request(request: &SetupRequest, members: &[SigningKey]) -> Result<(), MpcError> {
    if members.is_empty()
        || members.len() > 255
        || request.threshold == 0
        || usize::from(request.threshold) > members.len()
    {
        return Err(MpcError::InvalidThreshold);
    }
    // The exact `q = 1, d = 0` profile is accepted only by this explicitly
    // non-production test backend so an unmodified stock-regtest target
    // can be exercised. The mask still has its public prefix cleared and is
    // nonzero below it. Production/distributed adapters retain their stricter
    // nonzero-band validation.
    if !mask_parameters_valid(request.leading_zero_prefix_q, request.blind_band_bits_d) {
        return Err(MpcError::InvalidMaskParameters);
    }
    let unique: HashSet<_> = members
        .iter()
        .map(|key| key.verifying_key().to_bytes())
        .collect();
    if unique.len() != members.len() {
        return Err(MpcError::DuplicateMember);
    }
    Ok(())
}

fn reconstruct_verified(
    setup: &VssSetup,
    opening_shares: &[OpeningShare],
) -> Result<OpenedMask, MpcError> {
    if merkle_root(&setup.share_commitments) != setup.mask_commitment_root {
        return Err(MpcError::InvalidOpeningCommitment);
    }
    let mut valid = Vec::new();
    let mut seen_x = HashSet::new();
    for share in opening_shares {
        let Some(member_index) = setup
            .members
            .iter()
            .position(|member| member == &share.member_pubkey)
        else {
            return Err(MpcError::InvalidOpeningBinding);
        };
        if share.session_binding != setup.session_binding
            || share.x as usize != member_index + 1
            || !seen_x.insert(share.x)
        {
            return Err(MpcError::InvalidOpeningBinding);
        }
        let commitment = opening_commitment(
            &share.session_binding,
            &share.member_pubkey,
            share.x,
            &share.values,
        );
        if commitment != setup.share_commitments[member_index] {
            return Err(MpcError::InvalidOpeningCommitment);
        }
        verify_opening_signature(share)?;
        valid.push(share.clone());
    }
    if valid.len() < usize::from(setup.threshold) {
        return Err(MpcError::InsufficientOpeningShares);
    }
    valid.sort_by_key(|share| share.x);
    let mask = shamir_reconstruct(&valid[..usize::from(setup.threshold)]);
    if !mask_constraints_valid(&mask, setup.leading_zero_prefix_q, setup.blind_band_bits_d) {
        return Err(MpcError::MaskConstraintViolation);
    }
    if blake2b_256(&[&setup.parent_hash, &mask]) != setup.mask_hash {
        return Err(MpcError::MaskHashMismatch);
    }
    let opening_hashes: Vec<_> = valid
        .iter()
        .map(|share| {
            opening_commitment(
                &share.session_binding,
                &share.member_pubkey,
                share.x,
                &share.values,
            )
        })
        .collect();
    Ok(OpenedMask {
        mask,
        opening_transcript_root: merkle_root(&opening_hashes),
        valid_opening_members: valid.iter().map(|share| share.member_pubkey).collect(),
    })
}

fn fast_eval_transcript(setup: &VssSetup, raw_share_hash: &Hash256) -> Hash256 {
    let mut body = Encoder::new();
    body.fixed(&setup.session_binding);
    body.fixed(raw_share_hash);
    domain_hash("meshmine/fast-eval/v2", body.as_bytes())
}

fn generate_constrained_mask(rng: &mut impl RngCore, zero_prefix: u16, blind_bits: u16) -> Hash256 {
    debug_assert!(mask_parameters_valid(zero_prefix, blind_bits));
    loop {
        let mut mask = [0; 32];
        rng.fill_bytes(&mut mask);
        for bit in 0..zero_prefix {
            set_bit(&mut mask, bit, false);
        }
        let has_required_nonzero = if blind_bits == 0 {
            (zero_prefix..256).any(|bit| get_bit(&mask, bit))
        } else {
            (zero_prefix..zero_prefix + blind_bits).any(|bit| get_bit(&mask, bit))
        };
        if has_required_nonzero {
            return mask;
        }
    }
}

fn mask_constraints_valid(mask: &Hash256, zero_prefix: u16, blind_bits: u16) -> bool {
    if !mask_parameters_valid(zero_prefix, blind_bits) {
        return false;
    }
    let Some(blind_end) = zero_prefix
        .checked_add(blind_bits)
        .filter(|end| *end <= 256)
    else {
        return false;
    };
    (0..zero_prefix).all(|bit| !get_bit(mask, bit))
        && if blind_bits == 0 {
            (zero_prefix..256).any(|bit| get_bit(mask, bit))
        } else {
            (zero_prefix..blind_end).any(|bit| get_bit(mask, bit))
        }
}

fn mask_parameters_valid(zero_prefix: u16, blind_bits: u16) -> bool {
    zero_prefix != 0
        && (blind_bits != 0 || zero_prefix == 1)
        && zero_prefix
            .checked_add(blind_bits)
            .is_some_and(|end| end <= 256)
}

fn get_bit(bytes: &Hash256, bit: u16) -> bool {
    let byte = usize::from(bit / 8);
    let shift = 7 - (bit % 8);
    bytes[byte] & (1 << shift) != 0
}

fn set_bit(bytes: &mut Hash256, bit: u16, value: bool) {
    let byte = usize::from(bit / 8);
    let shift = 7 - (bit % 8);
    if value {
        bytes[byte] |= 1 << shift;
    } else {
        bytes[byte] &= !(1 << shift);
    }
}

fn shamir_split(
    secret: &Hash256,
    threshold: u8,
    share_count: u8,
    rng: &mut impl RngCore,
) -> Vec<Hash256> {
    let mut shares = vec![[0u8; 32]; usize::from(share_count)];
    for (byte_index, secret_byte) in secret.iter().enumerate() {
        let mut coefficients = vec![0u8; usize::from(threshold)];
        coefficients[0] = *secret_byte;
        rng.fill_bytes(&mut coefficients[1..]);
        for x in 1..=share_count {
            shares[usize::from(x - 1)][byte_index] = gf_eval(&coefficients, x);
        }
    }
    shares
}

fn shamir_reconstruct(shares: &[OpeningShare]) -> Hash256 {
    let mut secret = [0; 32];
    for (byte_index, secret_byte) in secret.iter_mut().enumerate() {
        let mut value = 0;
        for (index, share) in shares.iter().enumerate() {
            let mut basis = 1;
            for (other_index, other) in shares.iter().enumerate() {
                if index == other_index {
                    continue;
                }
                basis = gf_mul(basis, gf_div(other.x, other.x ^ share.x));
            }
            value ^= gf_mul(share.values[byte_index], basis);
        }
        *secret_byte = value;
    }
    secret
}

fn gf_eval(coefficients: &[u8], x: u8) -> u8 {
    coefficients
        .iter()
        .rev()
        .fold(0, |value, coefficient| gf_mul(value, x) ^ coefficient)
}

fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut product = 0;
    while right != 0 {
        if right & 1 != 0 {
            product ^= left;
        }
        let high = left & 0x80;
        left <<= 1;
        if high != 0 {
            left ^= 0x1b;
        }
        right >>= 1;
    }
    product
}

fn gf_pow(mut value: u8, mut exponent: u8) -> u8 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = gf_mul(result, value);
        }
        value = gf_mul(value, value);
        exponent >>= 1;
    }
    result
}

fn gf_div(numerator: u8, denominator: u8) -> u8 {
    debug_assert_ne!(denominator, 0);
    gf_mul(numerator, gf_pow(denominator, 254))
}

fn session_binding(request: &SetupRequest, mask_hash: &Hash256, members: &[[u8; 32]]) -> Hash256 {
    let mut body = Encoder::new();
    body.u16(request.protocol_version);
    body.u8(request.network_id);
    body.u16(request.lane_id);
    body.u64(request.session_sequence);
    body.fixed(&request.parent_hash);
    body.u16(request.leading_zero_prefix_q);
    body.u16(request.blind_band_bits_d);
    body.u8(request.threshold);
    body.u64(request.timed_open_after_ms);
    body.fixed(mask_hash);
    body.varint(members.len() as u64);
    for member in members {
        body.fixed(member);
    }
    domain_hash(SESSION_BINDING_DOMAIN, body.as_bytes())
}

fn opening_commitment(binding: &Hash256, pubkey: &[u8; 32], x: u8, values: &Hash256) -> Hash256 {
    let mut body = Encoder::new();
    body.fixed(binding);
    body.fixed(pubkey);
    body.u8(x);
    body.fixed(values);
    domain_hash(SHARE_COMMITMENT_DOMAIN, body.as_bytes())
}

fn opening_message(binding: &Hash256, pubkey: &[u8; 32], x: u8, values: &Hash256) -> Hash256 {
    let mut body = Encoder::new();
    body.fixed(binding);
    body.fixed(pubkey);
    body.u8(x);
    body.fixed(values);
    domain_hash(SHARE_SIGNATURE_DOMAIN, body.as_bytes())
}

fn verify_opening_signature(share: &OpeningShare) -> Result<(), MpcError> {
    let key = VerifyingKey::from_bytes(&share.member_pubkey)
        .map_err(|_| MpcError::InvalidOpeningSignature)?;
    let bytes: [u8; 64] = share
        .signature
        .0
        .as_slice()
        .try_into()
        .map_err(|_| MpcError::InvalidOpeningSignature)?;
    let signature = ed25519_dalek::Signature::from_bytes(&bytes);
    key.verify(
        &opening_message(
            &share.session_binding,
            &share.member_pubkey,
            share.x,
            &share.values,
        ),
        &signature,
    )
    .map_err(|_| MpcError::InvalidOpeningSignature)
}

fn setup_transcript_root(
    binding: &Hash256,
    mask_hash: &Hash256,
    commitment_root: &Hash256,
    members: &[[u8; 32]],
) -> Hash256 {
    let mut body = Encoder::new();
    body.fixed(binding);
    body.fixed(mask_hash);
    body.fixed(commitment_root);
    for member in members {
        body.fixed(member);
    }
    domain_hash(TRANSCRIPT_DOMAIN, body.as_bytes())
}

fn material_key(session: &Hash256, member: &[u8; 32]) -> String {
    format!("{}/{}", hex::encode(session), hex::encode(member))
}

fn logical_session_key(request: &SetupRequest) -> String {
    format!(
        "{}/{}/{}",
        request.network_id, request.lane_id, request.session_sequence
    )
}

fn vss_rng_seed(request: &SetupRequest) -> Hash256 {
    let mut encoder = Encoder::new();
    encoder.u16(request.protocol_version);
    encoder.u8(request.network_id);
    encoder.u16(request.lane_id);
    encoder.u64(request.session_sequence);
    encoder.fixed(&request.parent_hash);
    encoder.fixed(&request.deterministic_seed);
    domain_hash(VSS_RNG_DOMAIN, encoder.as_bytes())
}

fn encode_opening_share(share: &OpeningShare) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.fixed(&share.session_binding);
    encoder.fixed(&share.member_pubkey);
    encoder.u8(share.x);
    encoder.fixed(&share.values);
    encoder.bytes(&share.signature.0);
    encoder.into_bytes()
}

fn decode_opening_share(bytes: &[u8]) -> Result<OpeningShare, MpcError> {
    let mut decoder = Decoder::new(bytes, DecodeLimits::default())?;
    let share = OpeningShare {
        session_binding: decoder.array()?,
        member_pubkey: decoder.array()?,
        x: decoder.u8()?,
        values: decoder.array()?,
        signature: SignatureBytes(decoder.bytes(128)?),
    };
    decoder.finish()?;
    Ok(share)
}

#[cfg(test)]
mod tests {
    use meshmine_storage::{MemoryStore, RedbStore};

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

    fn keys() -> Vec<SigningKey> {
        (1..=5)
            .map(|byte| SigningKey::from_bytes(&[byte; 32]))
            .collect()
    }

    fn request() -> SetupRequest {
        SetupRequest {
            protocol_version: 2,
            network_id: 2,
            lane_id: 0,
            session_sequence: 1,
            parent_hash: [9; 32],
            leading_zero_prefix_q: 8,
            blind_band_bits_d: 8,
            threshold: 3,
            timed_open_after_ms: 1_000,
            deterministic_seed: [42; 32],
        }
    }

    #[test]
    fn logical_lane_sequence_cannot_be_rebound_to_a_new_mask() {
        let store = MemoryStore::default();
        let backend = DeterministicVssBackend::new(&store);
        backend.setup(&request(), &keys()).unwrap();
        // An exact retry is idempotent and reconstructs the same transcript.
        backend.setup(&request(), &keys()).unwrap();
        let mut conflicting = request();
        conflicting.deterministic_seed = [43; 32];
        assert!(matches!(
            backend.setup(&conflicting, &keys()),
            Err(MpcError::SessionReuse)
        ));
    }

    #[test]
    fn parallel_lanes_domain_separate_masks_even_if_caller_seed_repeats() {
        let store = MemoryStore::default();
        let backend = DeterministicVssBackend::new(&store);
        let first = backend.setup(&request(), &keys()).unwrap();
        let mut other_lane = request();
        other_lane.lane_id = 1;
        let second = backend.setup(&other_lane, &keys()).unwrap();
        assert_ne!(first.session_binding, second.session_binding);
        assert_ne!(first.mask_hash, second.mask_hash);
    }

    #[test]
    fn threshold_opening_is_durable_constrained_and_exact() {
        let directory = secure_tempdir().unwrap();
        let path = directory.path().join("mpc.redb");
        let setup;
        {
            let store = RedbStore::create(&path).unwrap();
            let backend = DeterministicVssBackend::new(&store);
            assert!(!backend.security_properties().production_eligible);
            setup = backend.setup(&request(), &keys()).unwrap();
        }

        // Simulate every participant and the original setup caller restarting.
        let store = RedbStore::create(&path).unwrap();
        let backend = DeterministicVssBackend::new(&store);
        let openings: Vec<_> = setup
            .members
            .iter()
            .map(|member| {
                backend
                    .load_opening(&setup.session_binding, member)
                    .unwrap()
            })
            .collect();
        let mut gate = TimedOpeningGate {
            phase: SessionPhase::ReceiptFinalizing,
            timed_open_after_ms: 1_000,
            accepted_boundary_fixed: false,
        };
        assert!(matches!(
            backend.timed_open(&setup, &openings[..3], &gate, 1_000),
            Err(MpcError::BoundaryNotFixed)
        ));
        gate.fix_receipt_boundary();
        assert!(matches!(
            backend.timed_open(&setup, &openings[..2], &gate, 1_000),
            Err(MpcError::InsufficientOpeningShares)
        ));
        let opened = backend
            .timed_open(&setup, &openings[..3], &gate, 1_000)
            .unwrap();
        assert!(mask_constraints_valid(&opened.mask, 8, 8));
        assert_eq!(
            blake2b_256(&[&request().parent_hash, &opened.mask]),
            setup.mask_hash
        );
    }

    #[test]
    fn stock_regtest_zero_blind_band_is_test_only_and_opens_exactly() {
        let store = MemoryStore::default();
        let backend = DeterministicVssBackend::new(&store);
        assert!(!backend.security_properties().production_eligible);

        let mut stock_regtest = request();
        stock_regtest.leading_zero_prefix_q = 1;
        stock_regtest.blind_band_bits_d = 0;
        stock_regtest.threshold = 2;
        stock_regtest.timed_open_after_ms = 0;
        let setup = backend.setup(&stock_regtest, &keys()).unwrap();
        assert_eq!(setup.leading_zero_prefix_q, 1);
        assert_eq!(setup.blind_band_bits_d, 0);

        let openings = setup
            .members
            .iter()
            .take(2)
            .map(|member| {
                backend
                    .load_opening(&setup.session_binding, member)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let opened = backend
            .timed_open(
                &setup,
                &openings,
                &TimedOpeningGate {
                    phase: SessionPhase::Opening,
                    timed_open_after_ms: 0,
                    accepted_boundary_fixed: true,
                },
                0,
            )
            .unwrap();

        assert!(!get_bit(&opened.mask, 0));
        assert!((1..256).any(|bit| get_bit(&opened.mask, bit)));
        assert!(mask_constraints_valid(&opened.mask, 1, 0));
        assert_eq!(
            blake2b_256(&[&stock_regtest.parent_hash, &opened.mask]),
            setup.mask_hash
        );
        backend.retire_after_audit(&setup, &opened).unwrap();
    }

    #[test]
    fn zero_blind_band_rejects_every_non_stock_test_prefix() {
        for leading_zero_prefix_q in [2, 8, 255, 256] {
            let mut unsupported = request();
            unsupported.leading_zero_prefix_q = leading_zero_prefix_q;
            unsupported.blind_band_bits_d = 0;
            assert!(matches!(
                DeterministicVssBackend::new(&MemoryStore::default()).setup(&unsupported, &keys()),
                Err(MpcError::InvalidMaskParameters)
            ));
        }
    }

    #[test]
    fn audited_retirement_erases_live_shares_and_survives_backup_restore() {
        let directory = secure_tempdir().unwrap();
        let path = directory.path().join("retired.redb");
        let setup;
        {
            let store = RedbStore::create(&path).unwrap();
            let backend = DeterministicVssBackend::new(&store);
            setup = backend.setup(&request(), &keys()).unwrap();
            let openings = setup
                .members
                .iter()
                .take(3)
                .map(|member| {
                    backend
                        .load_opening(&setup.session_binding, member)
                        .unwrap()
                })
                .collect::<Vec<_>>();
            let opened = backend
                .timed_open(
                    &setup,
                    &openings,
                    &TimedOpeningGate {
                        phase: SessionPhase::Opening,
                        timed_open_after_ms: 1_000,
                        accepted_boundary_fixed: true,
                    },
                    1_000,
                )
                .unwrap();
            backend.retire_after_audit(&setup, &opened).unwrap();
            assert!(
                backend
                    .public_retirement_transcript(&setup.session_binding)
                    .unwrap()
                    .is_some()
            );
            assert!(matches!(
                backend.load_opening(&setup.session_binding, &setup.members[0]),
                Err(MpcError::MissingOpeningMaterial)
            ));
            assert!(matches!(
                backend.setup(&request(), &keys()),
                Err(MpcError::SessionRetired)
            ));
        }

        // Restore a backup taken after the durable tombstone was committed.
        let restored_path = directory.path().join("restored.redb");
        std::fs::copy(&path, &restored_path).unwrap();
        let restored = RedbStore::create(&restored_path).unwrap();
        let backend = DeterministicVssBackend::new(&restored);
        assert!(matches!(
            backend.load_opening(&setup.session_binding, &setup.members[0]),
            Err(MpcError::MissingOpeningMaterial)
        ));
        assert!(matches!(
            backend.setup(&request(), &keys()),
            Err(MpcError::SessionRetired)
        ));
    }

    #[test]
    fn accepted_winner_survives_original_miner_exit_and_fast_abort() {
        let directory = secure_tempdir().unwrap();
        let store = RedbStore::create(directory.path().join("winner.redb")).unwrap();
        let backend = DeterministicVssBackend::new(&store);
        let setup = backend.setup(&request(), &keys()).unwrap();
        let accepted = vec![AcceptedShareHash {
            share_id: [7; 32],
            raw_share_hash: [0; 32],
        }];
        // No miner object is retained beyond this point.
        let openings: Vec<_> = setup
            .members
            .iter()
            .take(3)
            .map(|member| {
                backend
                    .load_opening(&setup.session_binding, member)
                    .unwrap()
            })
            .collect();
        let mut gate = TimedOpeningGate {
            phase: SessionPhase::Aborted,
            timed_open_after_ms: 1_000,
            accepted_boundary_fixed: true,
        };
        gate.abort_with_accepted_shares();
        let opened = backend.timed_open(&setup, &openings, &gate, 1_000).unwrap();
        let mut target = [0xff; 32];
        target[0] = 0x00;
        // q=8 ensures the opened mask (and raw=0 XOR mask) meets this target.
        assert_eq!(
            evaluate_accepted_winners(&opened, &accepted, &target),
            vec![[7; 32]]
        );
    }

    #[test]
    fn early_reveal_stops_assignments_and_uses_first_observation_cutoff() {
        let store = MemoryStore::default();
        let backend = DeterministicVssBackend::new(&store);
        let setup = backend.setup(&request(), &keys()).unwrap();
        let openings = setup
            .members
            .iter()
            .take(3)
            .map(|member| {
                backend
                    .load_opening(&setup.session_binding, member)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let opened = backend
            .timed_open(
                &setup,
                &openings,
                &TimedOpeningGate {
                    phase: SessionPhase::Opening,
                    timed_open_after_ms: 1_000,
                    accepted_boundary_fixed: true,
                },
                1_000,
            )
            .unwrap();
        let accepted = vec![
            TimestampedAcceptedShare {
                share: AcceptedShareHash {
                    share_id: [1; 32],
                    raw_share_hash: [0; 32],
                },
                accepted_at_ms: 499,
            },
            TimestampedAcceptedShare {
                share: AcceptedShareHash {
                    share_id: [2; 32],
                    raw_share_hash: [0; 32],
                },
                accepted_at_ms: 501,
            },
        ];
        let mut target = [0xff; 32];
        target[0] = 0;
        let outcome = backend
            .handle_and_retire_early_reveal(
                &setup,
                opened.mask,
                setup.members[0],
                500,
                &accepted,
                &target,
            )
            .unwrap();
        assert!(outcome.assignments_stopped && outcome.mask_permanently_retired);
        assert_eq!(outcome.eligible_share_ids, vec![[1; 32]]);
        assert_eq!(outcome.ineligible_share_ids, vec![[2; 32]]);
        assert_eq!(outcome.winner_share_ids, vec![[1; 32]]);
        assert!(matches!(
            backend.setup(&request(), &keys()),
            Err(MpcError::SessionRetired)
        ));
    }

    #[test]
    fn tampered_opening_share_fails_before_reconstruction() {
        let directory = secure_tempdir().unwrap();
        let store = RedbStore::create(directory.path().join("tamper.redb")).unwrap();
        let backend = DeterministicVssBackend::new(&store);
        let setup = backend.setup(&request(), &keys()).unwrap();
        let mut openings: Vec<_> = setup
            .members
            .iter()
            .take(3)
            .map(|member| {
                backend
                    .load_opening(&setup.session_binding, member)
                    .unwrap()
            })
            .collect();
        openings[0].values[0] ^= 1;
        let gate = TimedOpeningGate {
            phase: SessionPhase::Opening,
            timed_open_after_ms: 1_000,
            accepted_boundary_fixed: true,
        };
        assert!(matches!(
            backend.timed_open(&setup, &openings, &gate, 1_000),
            Err(MpcError::InvalidOpeningCommitment)
        ));
    }

    #[test]
    fn fast_path_reveals_only_false_for_loss_and_mask_for_win() {
        let directory = secure_tempdir().unwrap();
        let store = RedbStore::create(directory.path().join("fast.redb")).unwrap();
        let backend = DeterministicVssBackend::new(&store);
        let setup = backend.setup(&request(), &keys()).unwrap();
        let openings: Vec<_> = setup
            .members
            .iter()
            .take(3)
            .map(|member| {
                backend
                    .load_opening(&setup.session_binding, member)
                    .unwrap()
            })
            .collect();
        let mut target = [0xff; 32];
        target[0] = 0x00;

        let losing = backend
            .fast_evaluate(&setup, &openings, &[0xff; 32], &target, false)
            .unwrap();
        assert!(matches!(
            losing,
            FastEvalOutcome::Losing { winner: false, .. }
        ));

        let winning = backend
            .fast_evaluate(&setup, &openings, &[0; 32], &target, false)
            .unwrap();
        let close = backend
            .handle_and_retire_fast_winner(
                &setup,
                winning,
                [77; 32],
                50,
                &[
                    TimestampedAcceptedShare {
                        share: AcceptedShareHash {
                            share_id: [77; 32],
                            raw_share_hash: [0; 32],
                        },
                        accepted_at_ms: 49,
                    },
                    TimestampedAcceptedShare {
                        share: AcceptedShareHash {
                            share_id: [78; 32],
                            raw_share_hash: [1; 32],
                        },
                        accepted_at_ms: 51,
                    },
                ],
                &target,
            )
            .unwrap();
        assert_eq!(close.eligible_share_ids, vec![[77; 32]]);
        assert_eq!(close.ineligible_share_ids, vec![[78; 32]]);
        assert!(close.assignments_stopped && close.mask_permanently_retired);
        assert_eq!(
            blake2b_256(&[&setup.parent_hash, &close.opened.mask]),
            setup.mask_hash
        );
        assert!(matches!(
            backend.setup(&request(), &keys()),
            Err(MpcError::SessionRetired)
        ));
    }

    #[test]
    fn forced_fast_abort_falls_back_to_timed_winner_recovery() {
        let directory = secure_tempdir().unwrap();
        let store = RedbStore::create(directory.path().join("abort.redb")).unwrap();
        let backend = DeterministicVssBackend::new(&store);
        let setup = backend.setup(&request(), &keys()).unwrap();
        let openings: Vec<_> = setup
            .members
            .iter()
            .take(3)
            .map(|member| {
                backend
                    .load_opening(&setup.session_binding, member)
                    .unwrap()
            })
            .collect();
        let mut target = [0xff; 32];
        target[0] = 0;
        assert!(matches!(
            backend
                .fast_evaluate(&setup, &openings, &[0; 32], &target, true)
                .unwrap(),
            FastEvalOutcome::Aborted { .. }
        ));

        let gate = TimedOpeningGate {
            phase: SessionPhase::TimedRecovery,
            timed_open_after_ms: 1_000,
            accepted_boundary_fixed: true,
        };
        let opened = backend.timed_open(&setup, &openings, &gate, 1_000).unwrap();
        assert_eq!(
            evaluate_accepted_winners(
                &opened,
                &[AcceptedShareHash {
                    share_id: [88; 32],
                    raw_share_hash: [0; 32],
                }],
                &target
            ),
            vec![[88; 32]]
        );
    }
}
