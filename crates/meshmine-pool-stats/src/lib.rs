//! Public, endpoint-signed statistics for independently operated MeshMine nodes.
//!
//! This is the profile-specific endpoint object required by the draft HNSA
//! proposal. HNSA validation remains in `handshake-rs`; this crate does not
//! duplicate name-state, service-authorization, or endpoint-delegation logic.

use std::collections::BTreeMap;

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use meshmine_codec::{CodecError, DecodeLimits, Decoder, Encoder};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const SIGNATURE_DOMAIN: &[u8] = b"HNS-MESHMINE-POOL-STATS-V1\0";

pub const VERSION: u8 = 1;
pub const SERVICE_NAME: &str = "pool-stats";
/// Private experimental value pending an accepted HNSA profile assignment.
pub const EXPERIMENTAL_PROFILE_ID: u16 = 0xff00;
pub const READ_STATS_CAPABILITY: u32 = 1;
pub const MAX_SNAPSHOT_LIFETIME: u64 = 120;
pub const MAX_SNAPSHOT_SIZE: usize = 512;
pub const MAX_SIGNATURE_SIZE: usize = 80;
pub const MAX_DOCUMENT_OBJECT_SIZE: usize = 1024;
pub const MAX_AGGREGATE_OPERATORS: usize = 128;

#[derive(Debug, Error)]
pub enum PoolStatsError {
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error("invalid public pool statistics: {0}")]
    Invalid(&'static str),
    #[error("pool-statistics signature operation failed")]
    Cryptography,
    #[error("conflicting snapshots have the same operator sequence")]
    ConflictingSequence,
    #[error("public pool-statistics counter overflow")]
    CounterOverflow,
    #[error("invalid public pool-statistics document hex")]
    InvalidDocumentHex,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PublicMode {
    Bootstrapping = 0,
    Mining = 1,
    Degraded = 2,
    Fallback = 3,
    Draining = 4,
    Stopped = 5,
}

impl TryFrom<u8> for PublicMode {
    type Error = PoolStatsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Bootstrapping),
            1 => Ok(Self::Mining),
            2 => Ok(Self::Degraded),
            3 => Ok(Self::Fallback),
            4 => Ok(Self::Draining),
            5 => Ok(Self::Stopped),
            _ => Err(PoolStatsError::Invalid("unknown public operator mode")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FoundBlock {
    pub height: u32,
    pub hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolStatsSnapshotV1 {
    pub network_magic: u32,
    pub profile_id: u16,
    pub authorization_id: [u8; 32],
    pub delegation_id: [u8; 32],
    pub endpoint_sequence: u64,
    pub sequence: u64,
    pub generated_at: u64,
    pub expires_at: u64,
    pub operator_id: [u8; 32],
    pub tip_height: u32,
    pub tip_hash: [u8; 32],
    pub connected_miners: u32,
    pub connected_mesh_peers: u32,
    pub accepted_shares: u64,
    pub rejected_shares: u64,
    pub pending_captures: u32,
    pub last_found_block: Option<FoundBlock>,
    pub mode: PublicMode,
    pub production_eligible: bool,
    pub endpoint_signature: Vec<u8>,
}

impl PoolStatsSnapshotV1 {
    pub fn encode_unsigned(&self) -> Result<Vec<u8>, PoolStatsError> {
        self.validate_fields()?;
        let mut encoder = Encoder::new();
        encoder.u8(VERSION);
        encoder.u32(self.network_magic);
        encoder.u16(self.profile_id);
        encoder.fixed(&self.authorization_id);
        encoder.fixed(&self.delegation_id);
        encoder.u64(self.endpoint_sequence);
        encoder.u64(self.sequence);
        encoder.u64(self.generated_at);
        encoder.u64(self.expires_at);
        encoder.fixed(&self.operator_id);
        encoder.u32(self.tip_height);
        encoder.fixed(&self.tip_hash);
        encoder.u32(self.connected_miners);
        encoder.u32(self.connected_mesh_peers);
        encoder.u64(self.accepted_shares);
        encoder.u64(self.rejected_shares);
        encoder.u32(self.pending_captures);
        match self.last_found_block {
            None => encoder.u8(0),
            Some(block) => {
                encoder.u8(1);
                encoder.u32(block.height);
                encoder.fixed(&block.hash);
            }
        }
        encoder.u8(self.mode as u8);
        encoder.u8(u8::from(self.production_eligible));
        let encoded = encoder.into_bytes();
        if encoded.len() >= MAX_SNAPSHOT_SIZE {
            return Err(PoolStatsError::Invalid("snapshot exceeds size limit"));
        }
        Ok(encoded)
    }

    pub fn sign(&mut self, endpoint_key: &SigningKey) -> Result<(), PoolStatsError> {
        let unsigned = self.encode_unsigned()?;
        let signature: Signature = endpoint_key
            .sign_prehash(&signature_digest(&unsigned))
            .map_err(|_| PoolStatsError::Cryptography)?;
        let signature = signature.normalize_s().unwrap_or(signature);
        self.endpoint_signature = signature.to_der().as_bytes().to_vec();
        Ok(())
    }

    pub fn verify(&self, context: &PoolStatsTrustContext) -> Result<(), PoolStatsError> {
        self.validate_fields()?;
        if self.network_magic != context.network_magic
            || self.profile_id != context.profile_id
            || self.authorization_id != context.authorization_id
            || self.delegation_id != context.delegation_id
            || self.endpoint_sequence != context.endpoint_sequence
            || self.expires_at > context.delegation_expires_at
            || context.now < self.generated_at
            || context.now >= self.expires_at
        {
            return Err(PoolStatsError::Invalid("snapshot trust context mismatch"));
        }
        let signature = parse_signature(&self.endpoint_signature)?;
        let unsigned = self.encode_unsigned()?;
        VerifyingKey::from_sec1_bytes(&context.endpoint_key)
            .map_err(|_| PoolStatsError::Invalid("invalid HNSA endpoint key"))?
            .verify_prehash(&signature_digest(&unsigned), &signature)
            .map_err(|_| PoolStatsError::Cryptography)
    }

    pub fn encode(&self) -> Result<Vec<u8>, PoolStatsError> {
        let unsigned = self.encode_unsigned()?;
        parse_signature(&self.endpoint_signature)?;
        let mut encoder = Encoder::new();
        encoder.fixed(&unsigned);
        encoder.u8(u8::try_from(self.endpoint_signature.len())
            .map_err(|_| PoolStatsError::Invalid("signature exceeds size limit"))?);
        encoder.fixed(&self.endpoint_signature);
        let encoded = encoder.into_bytes();
        if encoded.len() > MAX_SNAPSHOT_SIZE {
            return Err(PoolStatsError::Invalid("snapshot exceeds size limit"));
        }
        Ok(encoded)
    }

    pub fn decode(input: &[u8]) -> Result<Self, PoolStatsError> {
        if input.is_empty() || input.len() > MAX_SNAPSHOT_SIZE {
            return Err(PoolStatsError::Invalid("invalid snapshot size"));
        }
        let mut decoder = Decoder::new(
            input,
            DecodeLimits {
                max_object_bytes: MAX_SNAPSHOT_SIZE,
                max_vector_items: 1,
            },
        )?;
        if decoder.u8()? != VERSION {
            return Err(PoolStatsError::Invalid("unsupported snapshot version"));
        }
        let network_magic = decoder.u32()?;
        let profile_id = decoder.u16()?;
        let authorization_id = decoder.array()?;
        let delegation_id = decoder.array()?;
        let endpoint_sequence = decoder.u64()?;
        let sequence = decoder.u64()?;
        let generated_at = decoder.u64()?;
        let expires_at = decoder.u64()?;
        let operator_id = decoder.array()?;
        let tip_height = decoder.u32()?;
        let tip_hash = decoder.array()?;
        let connected_miners = decoder.u32()?;
        let connected_mesh_peers = decoder.u32()?;
        let accepted_shares = decoder.u64()?;
        let rejected_shares = decoder.u64()?;
        let pending_captures = decoder.u32()?;
        let last_found_block = match decoder.u8()? {
            0 => None,
            1 => Some(FoundBlock {
                height: decoder.u32()?,
                hash: decoder.array()?,
            }),
            _ => return Err(PoolStatsError::Invalid("invalid found-block option")),
        };
        let mode = PublicMode::try_from(decoder.u8()?)?;
        let production_eligible = match decoder.u8()? {
            0 => false,
            1 => true,
            _ => return Err(PoolStatsError::Invalid("invalid production flag")),
        };
        let signature_length = decoder.u8()? as usize;
        if !(1..=MAX_SIGNATURE_SIZE).contains(&signature_length)
            || decoder.remaining() != signature_length
        {
            return Err(PoolStatsError::Invalid("invalid signature length"));
        }
        let endpoint_signature = decoder.fixed_bytes(signature_length, MAX_SIGNATURE_SIZE)?;
        decoder.finish()?;
        let snapshot = Self {
            network_magic,
            profile_id,
            authorization_id,
            delegation_id,
            endpoint_sequence,
            sequence,
            generated_at,
            expires_at,
            operator_id,
            tip_height,
            tip_hash,
            connected_miners,
            connected_mesh_peers,
            accepted_shares,
            rejected_shares,
            pending_captures,
            last_found_block,
            mode,
            production_eligible,
            endpoint_signature,
        };
        snapshot.encode_unsigned()?;
        parse_signature(&snapshot.endpoint_signature)?;
        Ok(snapshot)
    }

    fn validate_fields(&self) -> Result<(), PoolStatsError> {
        if self.profile_id != EXPERIMENTAL_PROFILE_ID
            || is_zero(&self.authorization_id)
            || is_zero(&self.delegation_id)
            || self.endpoint_sequence == 0
            || self.sequence == 0
            || is_zero(&self.operator_id)
            || self.expires_at <= self.generated_at
            || self.expires_at.saturating_sub(self.generated_at) > MAX_SNAPSHOT_LIFETIME
            || self
                .last_found_block
                .is_some_and(|block| block.height > self.tip_height)
        {
            return Err(PoolStatsError::Invalid("invalid bounded snapshot fields"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolStatsTrustContext {
    pub network_magic: u32,
    pub profile_id: u16,
    pub authorization_id: [u8; 32],
    pub delegation_id: [u8; 32],
    pub endpoint_sequence: u64,
    pub endpoint_key: [u8; 33],
    pub delegation_expires_at: u64,
    pub now: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolStatsDocumentV1 {
    pub schema: String,
    pub service_name: String,
    pub profile_id: u16,
    pub service_authorization: String,
    pub endpoint_delegation: String,
    pub snapshot: String,
}

impl PoolStatsDocumentV1 {
    pub fn new(
        service_authorization: &[u8],
        endpoint_delegation: &[u8],
        snapshot: &PoolStatsSnapshotV1,
    ) -> Result<Self, PoolStatsError> {
        if service_authorization.is_empty()
            || service_authorization.len() > MAX_DOCUMENT_OBJECT_SIZE
            || endpoint_delegation.is_empty()
            || endpoint_delegation.len() > MAX_DOCUMENT_OBJECT_SIZE
        {
            return Err(PoolStatsError::Invalid("invalid HNSA document object size"));
        }
        Ok(Self {
            schema: "meshmine-pool-stats-v1".to_owned(),
            service_name: SERVICE_NAME.to_owned(),
            profile_id: EXPERIMENTAL_PROFILE_ID,
            service_authorization: hex::encode(service_authorization),
            endpoint_delegation: hex::encode(endpoint_delegation),
            snapshot: hex::encode(snapshot.encode()?),
        })
    }

    pub fn decode_objects(
        &self,
    ) -> Result<(Vec<u8>, Vec<u8>, PoolStatsSnapshotV1), PoolStatsError> {
        if self.schema != "meshmine-pool-stats-v1"
            || self.service_name != SERVICE_NAME
            || self.profile_id != EXPERIMENTAL_PROFILE_ID
        {
            return Err(PoolStatsError::Invalid(
                "unsupported pool-statistics document",
            ));
        }
        let authorization = decode_document_hex(&self.service_authorization)?;
        let delegation = decode_document_hex(&self.endpoint_delegation)?;
        let snapshot = decode_document_hex(&self.snapshot)?;
        Ok((
            authorization,
            delegation,
            PoolStatsSnapshotV1::decode(&snapshot)?,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PublicTip {
    pub height: u32,
    pub hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TipGroup {
    pub tip: PublicTip,
    pub operators: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PoolStatsAggregate {
    pub operators: u32,
    pub connected_miners: u64,
    pub connected_mesh_peers: u64,
    pub accepted_shares: u64,
    pub rejected_shares: u64,
    pub pending_captures: u64,
    pub production_eligible_operators: u32,
    pub tips: Vec<TipGroup>,
}

/// Aggregate already-verified snapshots without introducing a central signer.
///
/// One latest snapshot is selected per operator. Equal sequence numbers with
/// different canonical bytes fail closed.
pub fn aggregate_verified(
    snapshots: &[PoolStatsSnapshotV1],
) -> Result<PoolStatsAggregate, PoolStatsError> {
    if snapshots.len() > MAX_AGGREGATE_OPERATORS {
        return Err(PoolStatsError::Invalid("too many operator snapshots"));
    }
    let mut selected = BTreeMap::<[u8; 32], &PoolStatsSnapshotV1>::new();
    for snapshot in snapshots {
        match selected.get(&snapshot.operator_id) {
            None => {
                selected.insert(snapshot.operator_id, snapshot);
            }
            Some(current) if snapshot.sequence > current.sequence => {
                selected.insert(snapshot.operator_id, snapshot);
            }
            Some(current)
                if snapshot.sequence == current.sequence
                    && snapshot.encode()? != current.encode()? =>
            {
                return Err(PoolStatsError::ConflictingSequence);
            }
            _ => {}
        }
    }

    let mut aggregate = PoolStatsAggregate {
        operators: u32::try_from(selected.len()).map_err(|_| PoolStatsError::CounterOverflow)?,
        connected_miners: 0,
        connected_mesh_peers: 0,
        accepted_shares: 0,
        rejected_shares: 0,
        pending_captures: 0,
        production_eligible_operators: 0,
        tips: Vec::new(),
    };
    let mut tips = BTreeMap::<PublicTip, u32>::new();
    for snapshot in selected.values() {
        aggregate.connected_miners = checked_add(
            aggregate.connected_miners,
            u64::from(snapshot.connected_miners),
        )?;
        aggregate.connected_mesh_peers = checked_add(
            aggregate.connected_mesh_peers,
            u64::from(snapshot.connected_mesh_peers),
        )?;
        aggregate.accepted_shares =
            checked_add(aggregate.accepted_shares, snapshot.accepted_shares)?;
        aggregate.rejected_shares =
            checked_add(aggregate.rejected_shares, snapshot.rejected_shares)?;
        aggregate.pending_captures = checked_add(
            aggregate.pending_captures,
            u64::from(snapshot.pending_captures),
        )?;
        if snapshot.production_eligible {
            aggregate.production_eligible_operators = aggregate
                .production_eligible_operators
                .checked_add(1)
                .ok_or(PoolStatsError::CounterOverflow)?;
        }
        let tip = PublicTip {
            height: snapshot.tip_height,
            hash: snapshot.tip_hash,
        };
        let operators = tips.entry(tip).or_default();
        *operators = operators
            .checked_add(1)
            .ok_or(PoolStatsError::CounterOverflow)?;
    }
    aggregate.tips = tips
        .into_iter()
        .map(|(tip, operators)| TipGroup { tip, operators })
        .collect();
    Ok(aggregate)
}

pub fn endpoint_public_key(endpoint_key: &SigningKey) -> [u8; 33] {
    endpoint_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed secp256k1 key is 33 bytes")
}

/// Responsive read-only view for ordinary desktop and mobile browsers.
///
/// The page decodes the signed snapshot for display. It deliberately labels
/// the result as unverified because cryptographic trust belongs in an
/// HNSA-aware client, not JavaScript supplied by the same endpoint.
pub fn public_stats_html() -> &'static str {
    r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MeshMine Pool Statistics</title><style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#0b1512;color:#eef8f3}body{margin:0;padding:20px;max-width:900px;margin-inline:auto}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}.card{padding:15px;border:1px solid #274238;border-radius:10px;background:#10231c}.label{color:#aec4ba;font-size:.8rem}.value{font-size:1.35rem;font-weight:700;margin-top:4px;overflow-wrap:anywhere}.notice{padding:12px 14px;border:1px solid #765f28;border-radius:8px;background:#2c2614;color:#eadba7;line-height:1.4}.bad{color:#ff8a80}code{overflow-wrap:anywhere}
</style></head><body><p>HNS / HNSA · read only</p><h1>MeshMine pool statistics</h1>
<p id="state" class="notice">Loading signed snapshot…</p><div class="grid">
<div class="card"><div class="label">Mode</div><div id="mode" class="value">—</div></div>
<div class="card"><div class="label">Connected miners</div><div id="miners" class="value">—</div></div>
<div class="card"><div class="label">Mesh peers</div><div id="peers" class="value">—</div></div>
<div class="card"><div class="label">Accepted shares</div><div id="accepted" class="value">—</div></div>
<div class="card"><div class="label">Rejected shares</div><div id="rejected" class="value">—</div></div>
<div class="card"><div class="label">Pending captures</div><div id="pending" class="value">—</div></div>
<div class="card"><div class="label">Handshake tip</div><div id="tip" class="value">—</div></div>
<div class="card"><div class="label">Snapshot sequence</div><div id="sequence" class="value">—</div></div>
</div><p>Operator <code id="operator">—</code></p><p>Valid until <span id="expires">—</span></p>
<script>
const $=id=>document.getElementById(id),modes=['bootstrapping','mining','degraded','fallback','draining','stopped'];
function bytes(hex){if(typeof hex!=='string'||hex.length%2||hex.length>1024)throw Error('invalid bounded snapshot');const out=new Uint8Array(hex.length/2);for(let i=0;i<out.length;i++){const n=Number.parseInt(hex.slice(i*2,i*2+2),16);if(!Number.isFinite(n))throw Error('invalid snapshot hex');out[i]=n}return out}
function read(hex){const b=bytes(hex),v=new DataView(b.buffer),r={o:0,u8(){return v.getUint8(this.o++)},u16(){const x=v.getUint16(this.o,true);this.o+=2;return x},u32(){const x=v.getUint32(this.o,true);this.o+=4;return x},u64(){const x=v.getBigUint64(this.o,true);this.o+=8;return x},take(n){const x=b.slice(this.o,this.o+n);this.o+=n;return [...x].map(x=>x.toString(16).padStart(2,'0')).join('')}};if(r.u8()!==1)throw Error('unsupported snapshot');r.u32();if(r.u16()!==0xff00)throw Error('unsupported profile');r.take(32);r.take(32);const endpointSequence=r.u64(),sequence=r.u64(),generated=r.u64(),expires=r.u64(),operator=r.take(32),height=r.u32(),hash=r.take(32),miners=r.u32(),peers=r.u32(),accepted=r.u64(),rejected=r.u64(),pending=r.u32(),found=r.u8();if(endpointSequence===0n||sequence===0n)throw Error('invalid snapshot sequence');if(found===1){r.u32();r.take(32)}else if(found!==0)throw Error('invalid snapshot');const mode=r.u8(),production=r.u8();return{sequence,generated,expires,operator,height,hash,miners,peers,accepted,rejected,pending,mode,production}}
async function refresh(){try{const q=await fetch('/api/v1/pool-stats',{cache:'no-store'});if(!q.ok)throw Error('HTTP '+q.status);const d=await q.json();if(d.schema!=='meshmine-pool-stats-v1'||d.service_name!=='pool-stats'||d.profile_id!==0xff00||!d.service_authorization||!d.endpoint_delegation)throw Error('invalid feed document');const s=read(d.snapshot);$('mode').textContent=modes[s.mode]??'unknown';$('miners').textContent=s.miners;$('peers').textContent=s.peers;$('accepted').textContent=s.accepted.toString();$('rejected').textContent=s.rejected.toString();$('pending').textContent=s.pending;$('tip').textContent=s.height+' · '+s.hash.slice(0,16)+'…';$('sequence').textContent=s.sequence.toString();$('operator').textContent=s.operator;$('expires').textContent=new Date(Number(s.expires)*1000).toLocaleString();const stale=BigInt(Math.floor(Date.now()/1000))>=s.expires;$('state').className='notice '+(stale?'bad':'');$('state').textContent=(stale?'Expired':'Signed snapshot and HNSA proof objects attached')+' — this page decodes data only; use an HNSA-aware client for cryptographic verification.'}catch(e){$('state').className='notice bad';$('state').textContent=e.message}}
refresh();setInterval(refresh,5000);
</script></body></html>"#
}

fn signature_digest(unsigned: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output length");
    hasher.update(SIGNATURE_DOMAIN);
    hasher.update(&unsigned[1..]);
    let mut output = [0; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("valid BLAKE2b output buffer");
    output
}

fn parse_signature(bytes: &[u8]) -> Result<Signature, PoolStatsError> {
    if bytes.is_empty() || bytes.len() > MAX_SIGNATURE_SIZE {
        return Err(PoolStatsError::Invalid("invalid signature length"));
    }
    let signature = Signature::from_der(bytes).map_err(|_| PoolStatsError::Cryptography)?;
    if signature.normalize_s().is_some() {
        return Err(PoolStatsError::Cryptography);
    }
    Ok(signature)
}

fn decode_document_hex(value: &str) -> Result<Vec<u8>, PoolStatsError> {
    if value.is_empty() || value.len() > MAX_DOCUMENT_OBJECT_SIZE.saturating_mul(2) {
        return Err(PoolStatsError::InvalidDocumentHex);
    }
    hex::decode(value).map_err(|_| PoolStatsError::InvalidDocumentHex)
}

fn checked_add(left: u64, right: u64) -> Result<u64, PoolStatsError> {
    left.checked_add(right)
        .ok_or(PoolStatsError::CounterOverflow)
}

fn is_zero(value: &[u8]) -> bool {
    value.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed(
        sequence: u64,
        operator_id: [u8; 32],
    ) -> (PoolStatsSnapshotV1, PoolStatsTrustContext) {
        let key = SigningKey::from_bytes((&[3; 32]).into()).expect("key");
        let mut snapshot = PoolStatsSnapshotV1 {
            network_magic: 0x6d6f6f6e,
            profile_id: EXPERIMENTAL_PROFILE_ID,
            authorization_id: [1; 32],
            delegation_id: [2; 32],
            endpoint_sequence: 1,
            sequence,
            generated_at: 1_700_000_000,
            expires_at: 1_700_000_060,
            operator_id,
            tip_height: 100,
            tip_hash: [4; 32],
            connected_miners: 2,
            connected_mesh_peers: 3,
            accepted_shares: 5,
            rejected_shares: 1,
            pending_captures: 1,
            last_found_block: Some(FoundBlock {
                height: 99,
                hash: [5; 32],
            }),
            mode: PublicMode::Mining,
            production_eligible: false,
            endpoint_signature: Vec::new(),
        };
        snapshot.sign(&key).expect("sign");
        let context = PoolStatsTrustContext {
            network_magic: snapshot.network_magic,
            profile_id: snapshot.profile_id,
            authorization_id: snapshot.authorization_id,
            delegation_id: snapshot.delegation_id,
            endpoint_sequence: snapshot.endpoint_sequence,
            endpoint_key: endpoint_public_key(&key),
            delegation_expires_at: 1_700_000_100,
            now: 1_700_000_010,
        };
        (snapshot, context)
    }

    #[test]
    fn snapshot_round_trip_binds_hnsa_context() {
        let (snapshot, context) = signed(1, [6; 32]);
        snapshot.verify(&context).expect("verified");
        let encoded = snapshot.encode().expect("encode");
        assert_eq!(
            PoolStatsSnapshotV1::decode(&encoded).expect("decode"),
            snapshot
        );

        let mut wrong = context;
        wrong.delegation_id[0] ^= 1;
        assert!(snapshot.verify(&wrong).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(PoolStatsSnapshotV1::decode(&trailing).is_err());

        let mut zero_endpoint_sequence = snapshot.clone();
        zero_endpoint_sequence.endpoint_sequence = 0;
        assert!(zero_endpoint_sequence.encode_unsigned().is_err());
        let mut zero_snapshot_sequence = snapshot;
        zero_snapshot_sequence.sequence = 0;
        assert!(zero_snapshot_sequence.encode_unsigned().is_err());
    }

    #[test]
    fn public_document_is_bounded_and_contains_opaque_hnsa_objects() {
        let (snapshot, _) = signed(1, [6; 32]);
        let document = PoolStatsDocumentV1::new(&[7; 120], &[8; 140], &snapshot).expect("document");
        let json = serde_json::to_vec(&document).expect("json");
        let decoded: PoolStatsDocumentV1 = serde_json::from_slice(&json).expect("document");
        let (authorization, delegation, decoded_snapshot) =
            decoded.decode_objects().expect("objects");
        assert_eq!(authorization, vec![7; 120]);
        assert_eq!(delegation, vec![8; 140]);
        assert_eq!(decoded_snapshot, snapshot);
    }

    #[test]
    fn aggregate_selects_latest_per_operator_and_exposes_tip_disagreement() {
        let (old, _) = signed(1, [6; 32]);
        let (mut latest, _) = signed(2, [6; 32]);
        latest.connected_miners = 4;
        latest
            .sign(&SigningKey::from_bytes((&[3; 32]).into()).expect("key"))
            .expect("sign");
        let (mut other, _) = signed(1, [7; 32]);
        other.tip_hash = [9; 32];
        other
            .sign(&SigningKey::from_bytes((&[3; 32]).into()).expect("key"))
            .expect("sign");

        let aggregate = aggregate_verified(&[old, latest, other]).expect("aggregate");
        assert_eq!(aggregate.operators, 2);
        assert_eq!(aggregate.connected_miners, 6);
        assert_eq!(aggregate.tips.len(), 2);
    }

    #[test]
    fn equal_sequence_conflicts_fail_closed() {
        let (first, _) = signed(1, [6; 32]);
        let mut conflict = first.clone();
        conflict.connected_miners += 1;
        conflict
            .sign(&SigningKey::from_bytes((&[3; 32]).into()).expect("key"))
            .expect("sign");
        assert!(matches!(
            aggregate_verified(&[first, conflict]),
            Err(PoolStatsError::ConflictingSequence)
        ));
    }
}
