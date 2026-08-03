//! Identity-bound adapter for distributed MP-SPDZ mask setup.
//!
//! Each committee process verifies the same frozen runtime artifacts, imports
//! exactly one private output file, persists only its own opening share, and
//! publishes a signed commitment. Assembly consumes those public commitments;
//! it never accepts or transports the private shares.

use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use meshmine_codec::{DecodeLimits, Decoder, Encoder};
use meshmine_hns::{Hash256, blake2b_256, merkle_root};
use meshmine_storage::{DurableStore, StorageError};
use meshmine_types::{SignatureBytes, domain_hash};
use thiserror::Error;

use super::{
    BackendSecurityProperties, MATERIAL_NAMESPACE, MpcError, OpeningShare,
    RETIRED_SESSION_NAMESPACE, SESSION_RESERVATION_NAMESPACE, SetupRequest, VssSetup,
    decode_opening_share, encode_opening_share, logical_session_key, material_key,
    opening_commitment, opening_message, verify_opening_signature,
};

pub const MP_SPDZ_OUTPUT_MAGIC: u64 = 0x4d4d4453;
pub const MP_SPDZ_OUTPUT_VERSION: u64 = 1;
pub const MP_SPDZ_OUTPUT_RECORDS: usize = 103;
pub const MP_SPDZ_OUTPUT_BYTES: usize = MP_SPDZ_OUTPUT_RECORDS * 8;

const PUBLIC_RECORDS: usize = 71;
const CONTRIBUTION_NAMESPACE: &str = "mask-setup-contribution-mp-spdz-v1";
const PUBLIC_EVIDENCE_NAMESPACE: &str = "mask-setup-evidence-mp-spdz-v1";
const ARTIFACT_DOMAIN: &str = "meshmine/mp-spdz-artifact/v1";
const PUBLIC_OUTPUT_DOMAIN: &str = "meshmine/mp-spdz-public-output/v1";
const SESSION_DOMAIN: &str = "meshmine/mask-vss-session/mp-spdz/v1";
const CONTRIBUTION_DOMAIN: &str = "meshmine/mask-setup-contribution/mp-spdz/v1";
const TRANSCRIPT_DOMAIN: &str = "meshmine/mask-vss-transcript/mp-spdz/v1";

#[derive(Debug, Error)]
pub enum DistributedSetupError {
    #[error("invalid MP-SPDZ output: {0}")]
    InvalidOutput(&'static str),
    #[error("invalid or mismatched MP-SPDZ artifact: {0}")]
    InvalidArtifact(&'static str),
    #[error("MP-SPDZ artifact is not in the deployment allowlist")]
    ArtifactNotAllowed,
    #[error("invalid distributed committee: {0}")]
    InvalidCommittee(&'static str),
    #[error("local MP-SPDZ party does not match the canonical committee member")]
    LocalPartyMismatch,
    #[error("invalid distributed setup contribution: {0}")]
    InvalidContribution(&'static str),
    #[error("one durable setup contribution is required from every committee member")]
    IncompleteContributions,
    #[error("durable setup bytes conflict with an earlier import")]
    DurableConflict,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Codec(#[from] meshmine_codec::CodecError),
    #[error(transparent)]
    Mpc(#[from] MpcError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactFileIdentity {
    pub byte_len: u64,
    pub blake2b_256: Hash256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MpSpdzArtifactManifest {
    pub mp_spdz_revision: [u8; 20],
    pub build_environment_digest: Hash256,
    pub setup_source: ArtifactFileIdentity,
    pub mask_hash_circuit: ArtifactFileIdentity,
    pub bytecode: ArtifactFileIdentity,
    pub schedule: ArtifactFileIdentity,
    pub runtime_binary: ArtifactFileIdentity,
    pub runtime_library: ArtifactFileIdentity,
    pub leading_zero_prefix_q: u16,
    pub blind_band_bits_d: u16,
    pub members: u8,
    pub threshold: u8,
    pub integer_bit_length: u16,
    pub arithmetic_field_bits: u16,
    pub binary_register_bits: u16,
    pub statistical_security_bits: u16,
    pub classic_dabits: bool,
    pub preserve_memory_order: bool,
    pub little_endian_binary_output: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct MpSpdzArtifactPaths<'a> {
    pub setup_source: &'a Path,
    pub mask_hash_circuit: &'a Path,
    pub bytecode: &'a Path,
    pub schedule: &'a Path,
    pub runtime_binary: &'a Path,
    pub runtime_library: &'a Path,
}

#[derive(Clone, Debug)]
pub struct VerifiedMpSpdzArtifact {
    manifest: MpSpdzArtifactManifest,
    artifact_id: Hash256,
}

#[derive(Clone, Debug)]
pub struct ApprovedMpSpdzArtifact {
    verified: VerifiedMpSpdzArtifact,
}

#[derive(Clone, Debug, Default)]
pub struct ArtifactAllowlist {
    artifact_ids: HashSet<Hash256>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MpSpdzLocalOutput {
    pub leading_zero_prefix_q: u16,
    pub blind_band_bits_d: u16,
    pub members: u8,
    pub threshold: u8,
    pub parent_hash: Hash256,
    pub mask_hash: Hash256,
    pub local_share: Hash256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DistributedSetupContribution {
    pub artifact_id: Hash256,
    pub public_output_id: Hash256,
    pub session_binding: Hash256,
    pub mask_hash: Hash256,
    pub member_pubkey: [u8; 32],
    pub x: u8,
    pub share_commitment: Hash256,
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DistributedSetupAssembly {
    pub setup: VssSetup,
    pub artifact_id: Hash256,
    pub public_output_id: Hash256,
    pub contribution_root: Hash256,
}

impl MpSpdzArtifactManifest {
    pub fn artifact_id(&self) -> Hash256 {
        let mut body = Encoder::new();
        body.fixed(&self.mp_spdz_revision);
        body.fixed(&self.build_environment_digest);
        encode_artifact_file(&mut body, &self.setup_source);
        encode_artifact_file(&mut body, &self.mask_hash_circuit);
        encode_artifact_file(&mut body, &self.bytecode);
        encode_artifact_file(&mut body, &self.schedule);
        encode_artifact_file(&mut body, &self.runtime_binary);
        encode_artifact_file(&mut body, &self.runtime_library);
        body.u16(self.leading_zero_prefix_q);
        body.u16(self.blind_band_bits_d);
        body.u8(self.members);
        body.u8(self.threshold);
        body.u16(self.integer_bit_length);
        body.u16(self.arithmetic_field_bits);
        body.u16(self.binary_register_bits);
        body.u16(self.statistical_security_bits);
        body.u8(u8::from(self.classic_dabits));
        body.u8(u8::from(self.preserve_memory_order));
        body.u8(u8::from(self.little_endian_binary_output));
        body.u64(MP_SPDZ_OUTPUT_MAGIC);
        body.u64(MP_SPDZ_OUTPUT_VERSION);
        domain_hash(ARTIFACT_DOMAIN, body.as_bytes())
    }

    pub fn verify_files(
        &self,
        paths: MpSpdzArtifactPaths<'_>,
    ) -> Result<VerifiedMpSpdzArtifact, DistributedSetupError> {
        validate_manifest(self)?;
        verify_artifact_file(paths.setup_source, &self.setup_source)?;
        verify_artifact_file(paths.mask_hash_circuit, &self.mask_hash_circuit)?;
        verify_artifact_file(paths.bytecode, &self.bytecode)?;
        verify_artifact_file(paths.schedule, &self.schedule)?;
        verify_artifact_file(paths.runtime_binary, &self.runtime_binary)?;
        verify_artifact_file(paths.runtime_library, &self.runtime_library)?;
        Ok(VerifiedMpSpdzArtifact {
            manifest: self.clone(),
            artifact_id: self.artifact_id(),
        })
    }
}

impl VerifiedMpSpdzArtifact {
    pub fn manifest(&self) -> &MpSpdzArtifactManifest {
        &self.manifest
    }

    pub fn artifact_id(&self) -> Hash256 {
        self.artifact_id
    }
}

impl ArtifactAllowlist {
    pub fn new(artifact_ids: impl IntoIterator<Item = Hash256>) -> Self {
        Self {
            artifact_ids: artifact_ids.into_iter().collect(),
        }
    }

    pub fn allows(&self, artifact: &VerifiedMpSpdzArtifact) -> bool {
        self.artifact_ids.contains(&artifact.artifact_id)
    }

    pub fn authorize(
        &self,
        artifact: &VerifiedMpSpdzArtifact,
    ) -> Result<ApprovedMpSpdzArtifact, DistributedSetupError> {
        if !self.allows(artifact) {
            return Err(DistributedSetupError::ArtifactNotAllowed);
        }
        Ok(ApprovedMpSpdzArtifact {
            verified: artifact.clone(),
        })
    }
}

impl ApprovedMpSpdzArtifact {
    pub fn manifest(&self) -> &MpSpdzArtifactManifest {
        self.verified.manifest()
    }

    pub fn artifact_id(&self) -> Hash256 {
        self.verified.artifact_id()
    }
}

impl MpSpdzLocalOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self, DistributedSetupError> {
        if bytes.len() != MP_SPDZ_OUTPUT_BYTES {
            return Err(DistributedSetupError::InvalidOutput(
                "wrong binary record count",
            ));
        }
        let mut records = [0u64; MP_SPDZ_OUTPUT_RECORDS];
        for (index, chunk) in bytes.chunks_exact(8).enumerate() {
            let signed = i64::from_le_bytes(chunk.try_into().expect("fixed chunk"));
            if signed < 0 {
                return Err(DistributedSetupError::InvalidOutput(
                    "negative binary record",
                ));
            }
            records[index] = signed as u64;
        }
        if records[0] != MP_SPDZ_OUTPUT_MAGIC || records[1] != MP_SPDZ_OUTPUT_VERSION {
            return Err(DistributedSetupError::InvalidOutput(
                "wrong magic or version",
            ));
        }
        let leading_zero_prefix_q = u16::try_from(records[2])
            .map_err(|_| DistributedSetupError::InvalidOutput("q out of range"))?;
        let blind_band_bits_d = u16::try_from(records[3])
            .map_err(|_| DistributedSetupError::InvalidOutput("d out of range"))?;
        let members = u8::try_from(records[4])
            .map_err(|_| DistributedSetupError::InvalidOutput("member count out of range"))?;
        let threshold = u8::try_from(records[5])
            .map_err(|_| DistributedSetupError::InvalidOutput("threshold out of range"))?;
        if leading_zero_prefix_q == 0
            || blind_band_bits_d == 0
            || leading_zero_prefix_q
                .checked_add(blind_band_bits_d)
                .is_none_or(|end| end > 256)
            || members == 0
            || threshold == 0
            || threshold > members
        {
            return Err(DistributedSetupError::InvalidOutput(
                "invalid setup parameters",
            ));
        }
        if records[70] != 1 {
            return Err(DistributedSetupError::InvalidOutput(
                "blind-band rejection did not complete",
            ));
        }
        let parent_hash = decode_byte_records(&records[6..38])?;
        let mask_hash = decode_byte_records(&records[38..70])?;
        let local_share = decode_byte_records(&records[PUBLIC_RECORDS..])?;
        Ok(Self {
            leading_zero_prefix_q,
            blind_band_bits_d,
            members,
            threshold,
            parent_hash,
            mask_hash,
            local_share,
        })
    }

    pub fn read(path: &Path) -> Result<Self, DistributedSetupError> {
        if fs::metadata(path)?.len() != MP_SPDZ_OUTPUT_BYTES as u64 {
            return Err(DistributedSetupError::InvalidOutput(
                "wrong output file length",
            ));
        }
        Self::decode(&fs::read(path)?)
    }
}

/// Render the exact MP-SPDZ public input: bytes in canonical HNS order and
/// bits least-significant first within every byte.
pub fn render_parent_public_input(parent_hash: &Hash256) -> String {
    let mut output = String::with_capacity(32 * 16);
    for byte in parent_hash {
        for bit in 0..8 {
            if bit != 0 {
                output.push(' ');
            }
            output.push(if byte & (1 << bit) == 0 { '0' } else { '1' });
        }
        output.push('\n');
    }
    output
}

/// Create, flush, and sync a new public-input file. Refusing overwrite keeps a
/// stale parent from being silently reused under a new process invocation.
pub fn create_parent_public_input(
    path: &Path,
    parent_hash: &Hash256,
) -> Result<(), DistributedSetupError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(render_parent_public_input(parent_hash).as_bytes())?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

pub fn distributed_security_properties() -> BackendSecurityProperties {
    BackendSecurityProperties {
        // Protocol-level claim for the allowlisted MASCOT/Tinier pairing under
        // MP-SPDZ's stated corruption assumptions; not an implementation audit.
        malicious_secure: true,
        guaranteed_output_delivery: false,
        identifiable_abort: false,
        trusted_setup_coordinator: false,
        production_eligible: false,
    }
}

/// Persist one member's private share before returning its publishable setup
/// contribution. Neither this function nor its return value contains another
/// member's private share.
pub fn import_local_setup_output(
    store: &dyn DurableStore,
    request: &SetupRequest,
    members: &[[u8; 32]],
    local_signing_key: &SigningKey,
    party_index: u8,
    output: &MpSpdzLocalOutput,
    artifact: &ApprovedMpSpdzArtifact,
) -> Result<DistributedSetupContribution, DistributedSetupError> {
    let ordered = canonical_members(request, members)?;
    validate_profile(request, &ordered, output, artifact.manifest())?;
    let party = usize::from(party_index);
    if ordered.get(party) != Some(&local_signing_key.verifying_key().to_bytes()) {
        return Err(DistributedSetupError::LocalPartyMismatch);
    }

    let artifact_id = artifact.artifact_id();
    let public_output_id = public_output_id(request, &output.mask_hash, artifact.manifest());
    let session_binding =
        distributed_session_binding(request, &output.mask_hash, &artifact_id, &ordered);
    let member_pubkey = local_signing_key.verifying_key().to_bytes();
    let x = party_index
        .checked_add(1)
        .ok_or(DistributedSetupError::LocalPartyMismatch)?;
    let opening = OpeningShare {
        session_binding,
        member_pubkey,
        x,
        values: output.local_share,
        signature: SignatureBytes(
            local_signing_key
                .sign(&opening_message(
                    &session_binding,
                    &member_pubkey,
                    x,
                    &output.local_share,
                ))
                .to_bytes()
                .to_vec(),
        ),
    };
    let share_commitment =
        opening_commitment(&session_binding, &member_pubkey, x, &output.local_share);
    let mut contribution = DistributedSetupContribution {
        artifact_id,
        public_output_id,
        session_binding,
        mask_hash: output.mask_hash,
        member_pubkey,
        x,
        share_commitment,
        signature: SignatureBytes(Vec::new()),
    };
    contribution.signature = SignatureBytes(
        local_signing_key
            .sign(&contribution_message(&contribution))
            .to_bytes()
            .to_vec(),
    );

    reserve_session(store, request, &session_binding)?;
    persist_exact(
        store,
        PUBLIC_EVIDENCE_NAMESPACE,
        &hex::encode(session_binding),
        &encode_public_evidence(request, output, artifact_id, public_output_id),
    )?;
    persist_exact(
        store,
        MATERIAL_NAMESPACE,
        &material_key(&session_binding, &member_pubkey),
        &encode_opening_share(&opening),
    )?;
    // This is the publication barrier: callers receive the contribution only
    // after the private recovery material and public evidence are durable.
    persist_exact(
        store,
        CONTRIBUTION_NAMESPACE,
        &contribution_key(&session_binding, &member_pubkey),
        &encode_contribution(&contribution),
    )?;
    Ok(contribution)
}

pub fn load_local_opening(
    store: &dyn DurableStore,
    session_binding: &Hash256,
    member_pubkey: &[u8; 32],
) -> Result<OpeningShare, DistributedSetupError> {
    let bytes = store
        .get(
            MATERIAL_NAMESPACE,
            &material_key(session_binding, member_pubkey),
        )?
        .ok_or(MpcError::MissingOpeningMaterial)?;
    let opening = decode_opening_share(&bytes)?;
    if opening.session_binding != *session_binding || opening.member_pubkey != *member_pubkey {
        return Err(DistributedSetupError::InvalidContribution(
            "stored opening binding mismatch",
        ));
    }
    verify_opening_signature(&opening)?;
    Ok(opening)
}

pub fn load_local_contribution(
    store: &dyn DurableStore,
    session_binding: &Hash256,
    member_pubkey: &[u8; 32],
) -> Result<DistributedSetupContribution, DistributedSetupError> {
    let bytes = store
        .get(
            CONTRIBUTION_NAMESPACE,
            &contribution_key(session_binding, member_pubkey),
        )?
        .ok_or(DistributedSetupError::IncompleteContributions)?;
    let contribution = decode_contribution(&bytes)?;
    if contribution.session_binding != *session_binding
        || contribution.member_pubkey != *member_pubkey
    {
        return Err(DistributedSetupError::InvalidContribution(
            "stored contribution binding mismatch",
        ));
    }
    verify_contribution_signature(&contribution)?;
    Ok(contribution)
}

/// Assemble only public, signed commitments into the setup consumed by the
/// existing threshold-opening verifier.
pub fn assemble_distributed_setup(
    request: &SetupRequest,
    members: &[[u8; 32]],
    contributions: &[DistributedSetupContribution],
    artifact: &ApprovedMpSpdzArtifact,
) -> Result<DistributedSetupAssembly, DistributedSetupError> {
    let ordered = canonical_members(request, members)?;
    if contributions.len() != ordered.len() {
        return Err(DistributedSetupError::IncompleteContributions);
    }
    validate_manifest(artifact.manifest())?;
    if artifact.manifest().leading_zero_prefix_q != request.leading_zero_prefix_q
        || artifact.manifest().blind_band_bits_d != request.blind_band_bits_d
        || artifact.manifest().members as usize != ordered.len()
        || artifact.manifest().threshold != request.threshold
    {
        return Err(DistributedSetupError::InvalidArtifact(
            "profile does not match request",
        ));
    }

    let artifact_id = artifact.artifact_id();
    let mut seen = HashSet::new();
    let mut ordered_contributions = Vec::with_capacity(ordered.len());
    for (index, member) in ordered.iter().enumerate() {
        let contribution = contributions
            .iter()
            .find(|contribution| &contribution.member_pubkey == member)
            .ok_or(DistributedSetupError::IncompleteContributions)?;
        if !seen.insert(contribution.member_pubkey) || contribution.x as usize != index + 1 {
            return Err(DistributedSetupError::InvalidContribution(
                "duplicate member or wrong Shamir coordinate",
            ));
        }
        verify_contribution_signature(contribution)?;
        ordered_contributions.push(contribution.clone());
    }
    let mask_hash = ordered_contributions[0].mask_hash;
    let expected_public_output = public_output_id(request, &mask_hash, artifact.manifest());
    let expected_binding = distributed_session_binding(request, &mask_hash, &artifact_id, &ordered);
    for contribution in &ordered_contributions {
        if contribution.artifact_id != artifact_id
            || contribution.public_output_id != expected_public_output
            || contribution.session_binding != expected_binding
            || contribution.mask_hash != mask_hash
        {
            return Err(DistributedSetupError::InvalidContribution(
                "public MPC evidence differs across members",
            ));
        }
    }

    let commitments: Vec<_> = ordered_contributions
        .iter()
        .map(|contribution| contribution.share_commitment)
        .collect();
    let mask_commitment_root = merkle_root(&commitments);
    let contribution_hashes: Vec<_> = ordered_contributions
        .iter()
        .map(|contribution| domain_hash(CONTRIBUTION_DOMAIN, &encode_contribution(contribution)))
        .collect();
    let contribution_root = merkle_root(&contribution_hashes);
    let transcript_root = distributed_transcript_root(
        &expected_binding,
        &mask_hash,
        &mask_commitment_root,
        &artifact_id,
        &expected_public_output,
        &contribution_root,
        &ordered,
    );
    Ok(DistributedSetupAssembly {
        setup: VssSetup {
            session_binding: expected_binding,
            parent_hash: request.parent_hash,
            mask_hash,
            mask_commitment_root,
            transcript_root,
            leading_zero_prefix_q: request.leading_zero_prefix_q,
            blind_band_bits_d: request.blind_band_bits_d,
            threshold: request.threshold,
            timed_open_after_ms: request.timed_open_after_ms,
            members: ordered,
            share_commitments: commitments,
        },
        artifact_id,
        public_output_id: expected_public_output,
        contribution_root,
    })
}

/// Manifest for the exact ARM64 three-party conformance execution documented
/// in `mpc/mp-spdz/README.md`. It remains test-only and is not a normative
/// mainnet committee profile.
pub fn reviewed_three_party_fixture_manifest() -> MpSpdzArtifactManifest {
    MpSpdzArtifactManifest {
        mp_spdz_revision: decode_hex_array("6a2256e327b507918859f605735543bb32a39d9d"),
        build_environment_digest: decode_hex_array(
            "7c0cb4d30ba561558ad4696007e9f72839b3eb844e5772744ce6046ff1525bf4",
        ),
        setup_source: artifact_file(
            4_344,
            "f40986abfa8865789377feb025ca4c34659c1045021991baead780ec7f7a8b6d",
        ),
        mask_hash_circuit: artifact_file(
            5_683_435,
            "efcbf93386e192a1147f314375620701f919a25b1b9bb510ee2c78d44847c467",
        ),
        bytecode: artifact_file(
            5_454_016,
            "af2e3892d9c950ebf24cf5af0fe3d054f65667d34c646e6dab613318b8634479",
        ),
        schedule: artifact_file(
            161,
            "9783dbea21ef5215e346fd07a8d9dce164a4998f0aee124f52fd4b7be9f60034",
        ),
        runtime_binary: artifact_file(
            42_939_888,
            "1d501ce594aae0adf9a2e55c5dda8418d44c05b174f8612780220f81d9b76626",
        ),
        runtime_library: artifact_file(
            14_986_712,
            "e77c4de51cb35ebd998f39dd84d5a773cbaba813a717da5f544523bdf189da2b",
        ),
        leading_zero_prefix_q: 16,
        blind_band_bits_d: 8,
        members: 3,
        threshold: 2,
        integer_bit_length: 64,
        arithmetic_field_bits: 128,
        binary_register_bits: 64,
        statistical_security_bits: 40,
        classic_dabits: true,
        preserve_memory_order: true,
        little_endian_binary_output: true,
    }
}

fn validate_manifest(manifest: &MpSpdzArtifactManifest) -> Result<(), DistributedSetupError> {
    if manifest.leading_zero_prefix_q == 0
        || manifest.blind_band_bits_d == 0
        || manifest
            .leading_zero_prefix_q
            .checked_add(manifest.blind_band_bits_d)
            .is_none_or(|end| end > 256)
        || manifest.members == 0
        || manifest.threshold == 0
        || manifest.threshold > manifest.members
        || manifest.integer_bit_length != 64
        || manifest.arithmetic_field_bits < 128
        || manifest.binary_register_bits != 64
        || manifest.statistical_security_bits < 40
        || !manifest.classic_dabits
        || !manifest.preserve_memory_order
        || !manifest.little_endian_binary_output
    {
        return Err(DistributedSetupError::InvalidArtifact(
            "unsupported protocol profile",
        ));
    }
    if [
        &manifest.setup_source,
        &manifest.mask_hash_circuit,
        &manifest.bytecode,
        &manifest.schedule,
        &manifest.runtime_binary,
        &manifest.runtime_library,
    ]
    .iter()
    .any(|file| file.byte_len == 0)
    {
        return Err(DistributedSetupError::InvalidArtifact(
            "empty artifact identity",
        ));
    }
    Ok(())
}

fn validate_profile(
    request: &SetupRequest,
    members: &[[u8; 32]],
    output: &MpSpdzLocalOutput,
    manifest: &MpSpdzArtifactManifest,
) -> Result<(), DistributedSetupError> {
    validate_manifest(manifest)?;
    if output.parent_hash != request.parent_hash {
        return Err(DistributedSetupError::InvalidOutput(
            "parent does not match setup request",
        ));
    }
    if output.leading_zero_prefix_q != request.leading_zero_prefix_q
        || output.blind_band_bits_d != request.blind_band_bits_d
        || output.members as usize != members.len()
        || output.threshold != request.threshold
    {
        return Err(DistributedSetupError::InvalidOutput(
            "profile does not match setup request",
        ));
    }
    if manifest.leading_zero_prefix_q != output.leading_zero_prefix_q
        || manifest.blind_band_bits_d != output.blind_band_bits_d
        || manifest.members != output.members
        || manifest.threshold != output.threshold
    {
        return Err(DistributedSetupError::InvalidArtifact(
            "compiled profile does not match output",
        ));
    }
    Ok(())
}

fn canonical_members(
    request: &SetupRequest,
    members: &[[u8; 32]],
) -> Result<Vec<[u8; 32]>, DistributedSetupError> {
    if members.is_empty()
        || members.len() > 255
        || request.threshold == 0
        || usize::from(request.threshold) > members.len()
    {
        return Err(DistributedSetupError::InvalidCommittee(
            "invalid size or threshold",
        ));
    }
    if request.leading_zero_prefix_q == 0
        || request.blind_band_bits_d == 0
        || request
            .leading_zero_prefix_q
            .checked_add(request.blind_band_bits_d)
            .is_none_or(|end| end > 256)
    {
        return Err(DistributedSetupError::InvalidCommittee(
            "invalid mask parameters",
        ));
    }
    let mut ordered = members.to_vec();
    ordered.sort_unstable();
    if ordered.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(DistributedSetupError::InvalidCommittee(
            "duplicate public key",
        ));
    }
    for member in &ordered {
        VerifyingKey::from_bytes(member)
            .map_err(|_| DistributedSetupError::InvalidCommittee("invalid Ed25519 public key"))?;
    }
    Ok(ordered)
}

fn public_output_id(
    request: &SetupRequest,
    mask_hash: &Hash256,
    manifest: &MpSpdzArtifactManifest,
) -> Hash256 {
    let mut body = Encoder::new();
    body.fixed(&manifest.artifact_id());
    body.u64(MP_SPDZ_OUTPUT_MAGIC);
    body.u64(MP_SPDZ_OUTPUT_VERSION);
    body.u16(request.leading_zero_prefix_q);
    body.u16(request.blind_band_bits_d);
    body.u8(manifest.members);
    body.u8(request.threshold);
    body.fixed(&request.parent_hash);
    body.fixed(mask_hash);
    body.u8(1);
    domain_hash(PUBLIC_OUTPUT_DOMAIN, body.as_bytes())
}

fn distributed_session_binding(
    request: &SetupRequest,
    mask_hash: &Hash256,
    artifact_id: &Hash256,
    members: &[[u8; 32]],
) -> Hash256 {
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
    body.fixed(artifact_id);
    body.varint(members.len() as u64);
    for member in members {
        body.fixed(member);
    }
    domain_hash(SESSION_DOMAIN, body.as_bytes())
}

fn distributed_transcript_root(
    binding: &Hash256,
    mask_hash: &Hash256,
    commitment_root: &Hash256,
    artifact_id: &Hash256,
    public_output_id: &Hash256,
    contribution_root: &Hash256,
    members: &[[u8; 32]],
) -> Hash256 {
    let mut body = Encoder::new();
    body.fixed(binding);
    body.fixed(mask_hash);
    body.fixed(commitment_root);
    body.fixed(artifact_id);
    body.fixed(public_output_id);
    body.fixed(contribution_root);
    body.varint(members.len() as u64);
    for member in members {
        body.fixed(member);
    }
    domain_hash(TRANSCRIPT_DOMAIN, body.as_bytes())
}

fn contribution_message(contribution: &DistributedSetupContribution) -> Hash256 {
    let mut body = Encoder::new();
    body.fixed(&contribution.artifact_id);
    body.fixed(&contribution.public_output_id);
    body.fixed(&contribution.session_binding);
    body.fixed(&contribution.mask_hash);
    body.fixed(&contribution.member_pubkey);
    body.u8(contribution.x);
    body.fixed(&contribution.share_commitment);
    domain_hash(CONTRIBUTION_DOMAIN, body.as_bytes())
}

fn verify_contribution_signature(
    contribution: &DistributedSetupContribution,
) -> Result<(), DistributedSetupError> {
    let key = VerifyingKey::from_bytes(&contribution.member_pubkey)
        .map_err(|_| DistributedSetupError::InvalidContribution("invalid member public key"))?;
    let signature_bytes: [u8; 64] = contribution
        .signature
        .0
        .as_slice()
        .try_into()
        .map_err(|_| DistributedSetupError::InvalidContribution("invalid signature length"))?;
    key.verify(
        &contribution_message(contribution),
        &ed25519_dalek::Signature::from_bytes(&signature_bytes),
    )
    .map_err(|_| DistributedSetupError::InvalidContribution("signature verification failed"))
}

fn reserve_session(
    store: &dyn DurableStore,
    request: &SetupRequest,
    binding: &Hash256,
) -> Result<(), DistributedSetupError> {
    let reservation_key = logical_session_key(request);
    if let Some(existing) = store.get(SESSION_RESERVATION_NAMESPACE, &reservation_key)? {
        if store
            .get(RETIRED_SESSION_NAMESPACE, &hex::encode(&existing))?
            .is_some()
        {
            return Err(MpcError::SessionRetired.into());
        }
        if existing.as_slice() != binding {
            return Err(MpcError::SessionReuse.into());
        }
        return Ok(());
    }
    if !store.put_if_absent(SESSION_RESERVATION_NAMESPACE, &reservation_key, binding)? {
        let existing = store
            .get(SESSION_RESERVATION_NAMESPACE, &reservation_key)?
            .ok_or(DistributedSetupError::DurableConflict)?;
        if existing.as_slice() != binding {
            return Err(MpcError::SessionReuse.into());
        }
    }
    Ok(())
}

fn persist_exact(
    store: &dyn DurableStore,
    namespace: &str,
    key: &str,
    value: &[u8],
) -> Result<(), DistributedSetupError> {
    if store.put_if_absent(namespace, key, value)? {
        return Ok(());
    }
    if store.get(namespace, key)?.as_deref() == Some(value) {
        Ok(())
    } else {
        Err(DistributedSetupError::DurableConflict)
    }
}

fn encode_public_evidence(
    request: &SetupRequest,
    output: &MpSpdzLocalOutput,
    artifact_id: Hash256,
    public_output_id: Hash256,
) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.fixed(&artifact_id);
    encoder.fixed(&public_output_id);
    encoder.fixed(&request.parent_hash);
    encoder.fixed(&output.mask_hash);
    encoder.u16(output.leading_zero_prefix_q);
    encoder.u16(output.blind_band_bits_d);
    encoder.u8(output.members);
    encoder.u8(output.threshold);
    encoder.into_bytes()
}

fn encode_contribution(contribution: &DistributedSetupContribution) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.fixed(&contribution.artifact_id);
    encoder.fixed(&contribution.public_output_id);
    encoder.fixed(&contribution.session_binding);
    encoder.fixed(&contribution.mask_hash);
    encoder.fixed(&contribution.member_pubkey);
    encoder.u8(contribution.x);
    encoder.fixed(&contribution.share_commitment);
    encoder.bytes(&contribution.signature.0);
    encoder.into_bytes()
}

fn decode_contribution(
    bytes: &[u8],
) -> Result<DistributedSetupContribution, DistributedSetupError> {
    let mut decoder = Decoder::new(bytes, DecodeLimits::default())?;
    let contribution = DistributedSetupContribution {
        artifact_id: decoder.array()?,
        public_output_id: decoder.array()?,
        session_binding: decoder.array()?,
        mask_hash: decoder.array()?,
        member_pubkey: decoder.array()?,
        x: decoder.u8()?,
        share_commitment: decoder.array()?,
        signature: SignatureBytes(decoder.bytes(128)?),
    };
    decoder.finish()?;
    Ok(contribution)
}

fn contribution_key(session_binding: &Hash256, member_pubkey: &[u8; 32]) -> String {
    format!(
        "{}/{}",
        hex::encode(session_binding),
        hex::encode(member_pubkey)
    )
}

fn encode_artifact_file(encoder: &mut Encoder, file: &ArtifactFileIdentity) {
    encoder.u64(file.byte_len);
    encoder.fixed(&file.blake2b_256);
}

fn verify_artifact_file(
    path: &Path,
    expected: &ArtifactFileIdentity,
) -> Result<(), DistributedSetupError> {
    if fs::metadata(path)?.len() != expected.byte_len {
        return Err(DistributedSetupError::InvalidArtifact(
            "file length mismatch",
        ));
    }
    if blake2b_256(&[&fs::read(path)?]) != expected.blake2b_256 {
        return Err(DistributedSetupError::InvalidArtifact(
            "file digest mismatch",
        ));
    }
    Ok(())
}

fn decode_byte_records(records: &[u64]) -> Result<Hash256, DistributedSetupError> {
    let values: Vec<u8> = records
        .iter()
        .map(|value| {
            u8::try_from(*value)
                .map_err(|_| DistributedSetupError::InvalidOutput("byte record out of range"))
        })
        .collect::<Result<_, _>>()?;
    values
        .try_into()
        .map_err(|_| DistributedSetupError::InvalidOutput("wrong byte record count"))
}

fn artifact_file(byte_len: u64, digest: &str) -> ArtifactFileIdentity {
    ArtifactFileIdentity {
        byte_len,
        blake2b_256: decode_hex_array(digest),
    }
}

fn decode_hex_array<const N: usize>(value: &str) -> [u8; N] {
    let bytes = hex::decode(value).expect("frozen hexadecimal literal");
    bytes.try_into().expect("frozen hexadecimal length")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use meshmine_storage::{MemoryStore, RedbStore};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        DeterministicVssBackend, MpcBackend, SessionPhase, TimedOpeningGate,
        evaluate_accepted_winners, shamir_split,
    };

    fn secure_tempdir() -> std::io::Result<TempDir> {
        let directory = TempDir::new()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        }
        Ok(directory)
    }

    fn request() -> SetupRequest {
        SetupRequest {
            protocol_version: 2,
            network_id: 0,
            lane_id: 9,
            session_sequence: 44,
            parent_hash: [0x42; 32],
            leading_zero_prefix_q: 16,
            blind_band_bits_d: 8,
            threshold: 2,
            timed_open_after_ms: 50_000,
            deterministic_seed: [7; 32],
        }
    }

    fn ordered_keys() -> Vec<SigningKey> {
        let mut keys = vec![
            SigningKey::from_bytes(&[1; 32]),
            SigningKey::from_bytes(&[2; 32]),
            SigningKey::from_bytes(&[3; 32]),
        ];
        keys.sort_by_key(|key| key.verifying_key().to_bytes());
        keys
    }

    fn artifact_fixture(directory: &TempDir) -> (VerifiedMpSpdzArtifact, ApprovedMpSpdzArtifact) {
        let names = [
            "source", "circuit", "bytecode", "schedule", "runtime", "library",
        ];
        let paths: Vec<_> = names
            .iter()
            .enumerate()
            .map(|(index, name)| {
                let path = directory.path().join(name);
                fs::write(&path, vec![index as u8 + 1; index + 3]).unwrap();
                path
            })
            .collect();
        let identity = |path: &PathBuf| ArtifactFileIdentity {
            byte_len: fs::metadata(path).unwrap().len(),
            blake2b_256: blake2b_256(&[&fs::read(path).unwrap()]),
        };
        let manifest = MpSpdzArtifactManifest {
            mp_spdz_revision: [9; 20],
            build_environment_digest: [8; 32],
            setup_source: identity(&paths[0]),
            mask_hash_circuit: identity(&paths[1]),
            bytecode: identity(&paths[2]),
            schedule: identity(&paths[3]),
            runtime_binary: identity(&paths[4]),
            runtime_library: identity(&paths[5]),
            leading_zero_prefix_q: 16,
            blind_band_bits_d: 8,
            members: 3,
            threshold: 2,
            integer_bit_length: 64,
            arithmetic_field_bits: 128,
            binary_register_bits: 64,
            statistical_security_bits: 40,
            classic_dabits: true,
            preserve_memory_order: true,
            little_endian_binary_output: true,
        };
        let verified = manifest
            .verify_files(MpSpdzArtifactPaths {
                setup_source: &paths[0],
                mask_hash_circuit: &paths[1],
                bytecode: &paths[2],
                schedule: &paths[3],
                runtime_binary: &paths[4],
                runtime_library: &paths[5],
            })
            .unwrap();
        let allowlist = ArtifactAllowlist::new([verified.artifact_id()]);
        let approved = allowlist.authorize(&verified).unwrap();
        (verified, approved)
    }

    fn output_bytes(output: &MpSpdzLocalOutput) -> Vec<u8> {
        let mut records = Vec::with_capacity(MP_SPDZ_OUTPUT_RECORDS);
        records.extend([
            MP_SPDZ_OUTPUT_MAGIC,
            MP_SPDZ_OUTPUT_VERSION,
            u64::from(output.leading_zero_prefix_q),
            u64::from(output.blind_band_bits_d),
            u64::from(output.members),
            u64::from(output.threshold),
        ]);
        records.extend(output.parent_hash.map(u64::from));
        records.extend(output.mask_hash.map(u64::from));
        records.push(1);
        records.extend(output.local_share.map(u64::from));
        records
            .into_iter()
            .flat_map(|value| (value as i64).to_le_bytes())
            .collect()
    }

    fn outputs(request: &SetupRequest) -> (Hash256, Vec<MpSpdzLocalOutput>) {
        let mut mask = [0x5a; 32];
        mask[0] = 0;
        mask[1] = 0;
        mask[2] = 0x80;
        let mask_hash = blake2b_256(&[&request.parent_hash, &mask]);
        let mut rng = ChaCha20Rng::from_seed([4; 32]);
        let shares = shamir_split(&mask, 2, 3, &mut rng);
        let outputs = shares
            .into_iter()
            .map(|local_share| MpSpdzLocalOutput {
                leading_zero_prefix_q: 16,
                blind_band_bits_d: 8,
                members: 3,
                threshold: 2,
                parent_hash: request.parent_hash,
                mask_hash,
                local_share,
            })
            .collect();
        (mask, outputs)
    }

    #[test]
    fn output_contract_is_exact_and_rejects_malleability() {
        let request = request();
        let (_, outputs) = outputs(&request);
        let bytes = output_bytes(&outputs[0]);
        assert_eq!(bytes.len(), MP_SPDZ_OUTPUT_BYTES);
        assert_eq!(MpSpdzLocalOutput::decode(&bytes).unwrap(), outputs[0]);

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(MpSpdzLocalOutput::decode(&trailing).is_err());
        let mut negative = bytes.clone();
        negative[PUBLIC_RECORDS * 8..(PUBLIC_RECORDS + 1) * 8]
            .copy_from_slice(&(-1i64).to_le_bytes());
        assert!(MpSpdzLocalOutput::decode(&negative).is_err());
        let mut invalid_blind = bytes;
        invalid_blind[70 * 8..71 * 8].copy_from_slice(&0i64.to_le_bytes());
        assert!(MpSpdzLocalOutput::decode(&invalid_blind).is_err());
    }

    #[test]
    fn distributed_setup_rejects_test_only_zero_blind_band_everywhere() {
        let mut stock_regtest = request();
        stock_regtest.leading_zero_prefix_q = 1;
        stock_regtest.blind_band_bits_d = 0;
        let members = ordered_keys()
            .iter()
            .map(|key| key.verifying_key().to_bytes())
            .collect::<Vec<_>>();
        assert!(matches!(
            canonical_members(&stock_regtest, &members),
            Err(DistributedSetupError::InvalidCommittee(
                "invalid mask parameters"
            ))
        ));

        let (_, outputs) = outputs(&request());
        let mut encoded_output = output_bytes(&outputs[0]);
        encoded_output[2 * 8..3 * 8].copy_from_slice(&1u64.to_le_bytes());
        encoded_output[3 * 8..4 * 8].copy_from_slice(&0u64.to_le_bytes());
        assert!(matches!(
            MpSpdzLocalOutput::decode(&encoded_output),
            Err(DistributedSetupError::InvalidOutput(
                "invalid setup parameters"
            ))
        ));

        let mut manifest = reviewed_three_party_fixture_manifest();
        manifest.leading_zero_prefix_q = 1;
        manifest.blind_band_bits_d = 0;
        assert!(matches!(
            validate_manifest(&manifest),
            Err(DistributedSetupError::InvalidArtifact(
                "unsupported protocol profile"
            ))
        ));
    }

    #[test]
    fn public_parent_bits_are_lsb_first_and_create_new() {
        let mut parent = [0; 32];
        parent[0] = 0x81;
        parent[1] = 0x02;
        let rendered = render_parent_public_input(&parent);
        let mut lines = rendered.lines();
        assert_eq!(lines.next(), Some("1 0 0 0 0 0 0 1"));
        assert_eq!(lines.next(), Some("0 1 0 0 0 0 0 0"));
        assert_eq!(rendered.split_whitespace().count(), 256);

        let directory = secure_tempdir().unwrap();
        let path = directory.path().join("public-input");
        create_parent_public_input(&path, &parent).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), rendered);
        assert!(create_parent_public_input(&path, &parent).is_err());
    }

    #[test]
    fn artifact_verification_detects_even_same_length_mutation() {
        let directory = secure_tempdir().unwrap();
        let (verified, _) = artifact_fixture(&directory);
        let runtime = directory.path().join("runtime");
        let mut bytes = fs::read(&runtime).unwrap();
        bytes[0] ^= 1;
        fs::write(&runtime, bytes).unwrap();
        let manifest = verified.manifest();
        assert!(
            manifest
                .verify_files(MpSpdzArtifactPaths {
                    setup_source: &directory.path().join("source"),
                    mask_hash_circuit: &directory.path().join("circuit"),
                    bytecode: &directory.path().join("bytecode"),
                    schedule: &directory.path().join("schedule"),
                    runtime_binary: &runtime,
                    runtime_library: &directory.path().join("library"),
                })
                .is_err()
        );
    }

    #[test]
    fn each_member_persists_one_share_then_public_assembly_opens() {
        let request = request();
        let keys = ordered_keys();
        let members: Vec<_> = keys
            .iter()
            .map(|key| key.verifying_key().to_bytes())
            .collect();
        let directory = secure_tempdir().unwrap();
        let (_, artifact) = artifact_fixture(&directory);
        let (mask, outputs) = outputs(&request);
        let stores: Vec<_> = (0..3).map(|_| MemoryStore::default()).collect();
        let contributions: Vec<_> = (0..3)
            .map(|index| {
                import_local_setup_output(
                    &stores[index],
                    &request,
                    &members,
                    &keys[index],
                    index as u8,
                    &outputs[index],
                    &artifact,
                )
                .unwrap()
            })
            .collect();
        let assembled =
            assemble_distributed_setup(&request, &members, &contributions, &artifact).unwrap();
        let openings: Vec<_> = stores
            .iter()
            .zip(&members)
            .map(|(store, member)| {
                load_local_opening(store, &assembled.setup.session_binding, member).unwrap()
            })
            .collect();
        assert_ne!(openings[0].values, mask);
        let backend = DeterministicVssBackend::new(&stores[0]);
        assert!(matches!(
            backend.timed_open(
                &assembled.setup,
                &openings[..1],
                &TimedOpeningGate {
                    phase: SessionPhase::Opening,
                    timed_open_after_ms: 50_000,
                    accepted_boundary_fixed: true,
                },
                50_000,
            ),
            Err(MpcError::InsufficientOpeningShares)
        ));
        let opened = backend
            .timed_open(
                &assembled.setup,
                &openings[1..],
                &TimedOpeningGate {
                    phase: SessionPhase::Opening,
                    timed_open_after_ms: 50_000,
                    accepted_boundary_fixed: true,
                },
                50_000,
            )
            .unwrap();
        assert_eq!(opened.mask, mask);

        let network_pow = [0; 32];
        let raw_share_hash = std::array::from_fn(|index| network_pow[index] ^ mask[index]);
        let winners = evaluate_accepted_winners(
            &opened,
            &[crate::AcceptedShareHash {
                share_id: [0x99; 32],
                raw_share_hash,
            }],
            &[0; 32],
        );
        assert_eq!(winners, vec![[0x99; 32]]);
    }

    #[test]
    fn local_share_and_contribution_survive_redb_restart() {
        let request = request();
        let keys = ordered_keys();
        let members: Vec<_> = keys
            .iter()
            .map(|key| key.verifying_key().to_bytes())
            .collect();
        let directory = secure_tempdir().unwrap();
        let (_, artifact) = artifact_fixture(&directory);
        let (_, outputs) = outputs(&request);
        let database = directory.path().join("member.redb");
        let contribution = {
            let store = RedbStore::create(&database).unwrap();
            import_local_setup_output(
                &store,
                &request,
                &members,
                &keys[0],
                0,
                &outputs[0],
                &artifact,
            )
            .unwrap()
        };
        let restored = RedbStore::create(&database).unwrap();
        let opening = load_local_opening(
            &restored,
            &contribution.session_binding,
            &contribution.member_pubkey,
        )
        .unwrap();
        assert_eq!(opening.values, outputs[0].local_share);
        assert_eq!(
            load_local_contribution(
                &restored,
                &contribution.session_binding,
                &contribution.member_pubkey,
            )
            .unwrap(),
            contribution
        );
    }

    #[test]
    fn assembly_rejects_cross_member_public_equivocation() {
        let request = request();
        let keys = ordered_keys();
        let members: Vec<_> = keys
            .iter()
            .map(|key| key.verifying_key().to_bytes())
            .collect();
        let directory = secure_tempdir().unwrap();
        let (_, artifact) = artifact_fixture(&directory);
        let (_, mut outputs) = outputs(&request);
        outputs[1].mask_hash[0] ^= 1;
        let stores: Vec<_> = (0..3).map(|_| MemoryStore::default()).collect();
        let contributions: Vec<_> = (0..3)
            .map(|index| {
                import_local_setup_output(
                    &stores[index],
                    &request,
                    &members,
                    &keys[index],
                    index as u8,
                    &outputs[index],
                    &artifact,
                )
                .unwrap()
            })
            .collect();
        assert!(assemble_distributed_setup(&request, &members, &contributions, &artifact).is_err());
    }

    #[test]
    fn local_import_is_idempotent_but_rejects_rebinding_and_wrong_party() {
        let request = request();
        let keys = ordered_keys();
        let members: Vec<_> = keys
            .iter()
            .map(|key| key.verifying_key().to_bytes())
            .collect();
        let directory = secure_tempdir().unwrap();
        let (verified, artifact) = artifact_fixture(&directory);
        let (_, mut outputs) = outputs(&request);
        let store = MemoryStore::default();
        let first = import_local_setup_output(
            &store,
            &request,
            &members,
            &keys[0],
            0,
            &outputs[0],
            &artifact,
        )
        .unwrap();
        let retry = import_local_setup_output(
            &store,
            &request,
            &members,
            &keys[0],
            0,
            &outputs[0],
            &artifact,
        )
        .unwrap();
        assert_eq!(first, retry);

        outputs[0].mask_hash[0] ^= 1;
        assert!(matches!(
            import_local_setup_output(
                &store,
                &request,
                &members,
                &keys[0],
                0,
                &outputs[0],
                &artifact,
            ),
            Err(DistributedSetupError::Mpc(MpcError::SessionReuse))
        ));
        assert!(matches!(
            import_local_setup_output(
                &MemoryStore::default(),
                &request,
                &members,
                &keys[1],
                0,
                &outputs[1],
                &artifact,
            ),
            Err(DistributedSetupError::LocalPartyMismatch)
        ));
        assert!(matches!(
            ArtifactAllowlist::default().authorize(&verified),
            Err(DistributedSetupError::ArtifactNotAllowed)
        ));
    }

    #[test]
    fn distributed_security_boundary_is_not_a_production_claim() {
        let properties = distributed_security_properties();
        assert!(properties.malicious_secure);
        assert!(!properties.guaranteed_output_delivery);
        assert!(!properties.identifiable_abort);
        assert!(!properties.trusted_setup_coordinator);
        assert!(!properties.production_eligible);
        assert_eq!(
            hex::encode(reviewed_three_party_fixture_manifest().artifact_id()),
            "0524ed532663f4ef9342a20f9e9ac9eaf28dedf44785e7fdfe0629c5fc311906"
        );
    }
}
