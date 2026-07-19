use std::fmt;

use meshmine_codec::{CanonicalDecode, CanonicalEncode, CodecError, Decoder, Encoder};
use meshmine_hns::{Hash256, blake2b_256};
use thiserror::Error;

pub const CORE_V2: u16 = 2;
pub const GATEWAY_HANDOFF_V1: u16 = 1;
pub const GATEWAY_EXTRA_NONCE_PROFILE_HANDY_PREFIX4_VARIABLE4_ZERO16: u16 = 1;
pub const GATEWAY_OBSERVATION_CORE_RECEIPT_TIME: u16 = 1;
pub const GATEWAY_OBSERVATION_DELEGATED_SIGNED_TIME_V1: u16 = 2;
pub const MAX_GATEWAY_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;
pub const ED25519_SUITE: u16 = 1;
pub const MAX_ADDRESS_HASH_BYTES: usize = 64;
pub const MAX_CONTACT_METADATA_BYTES: usize = 32;
pub const MAX_SIGNATURE_BYTES: usize = 128;
pub const MAX_CERTIFICATE_SIGNERS: usize = 4096;
pub const MAX_OBJECT_HASHES: usize = 100_000;
pub const MAX_BUCKETS: usize = 100_000;
pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

pub type OperatorId = Hash256;
pub type PayoutBucketId = Hash256;
pub type ObjectId = Hash256;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct U256(pub [u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct U512(pub [u8; 64]);

impl U256 {
    pub const ZERO: Self = Self([0; 32]);
}

impl U512 {
    pub const ZERO: Self = Self([0; 64]);
}

impl fmt::Debug for U256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "U256({})", hex_debug(&self.0))
    }
}

impl fmt::Debug for U512 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "U512({})", hex_debug(&self.0))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureBytes(pub Vec<u8>);

impl SignatureBytes {
    pub fn empty() -> Self {
        Self(Vec::new())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerSignature {
    pub signer_pubkey: [u8; 32],
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureSet {
    pub signature_suite: u16,
    pub signatures: Vec<SignerSignature>,
}

impl SignatureSet {
    pub fn empty_ed25519() -> Self {
        Self {
            signature_suite: ED25519_SUITE,
            signatures: Vec::new(),
        }
    }

    pub fn validate_order(&self) -> Result<(), ObjectError> {
        if self
            .signatures
            .windows(2)
            .any(|pair| pair[0].signer_pubkey >= pair[1].signer_pubkey)
        {
            return Err(ObjectError::UnsortedSigners);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkBucketLeaf {
    pub bucket_id: PayoutBucketId,
    pub operator_pubkey: [u8; 32],
    pub hns_address_version: u8,
    pub hns_address_hash: Vec<u8>,
    pub credited_work: U512,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceBucketLeaf {
    pub bucket_id: PayoutBucketId,
    pub operator_pubkey: [u8; 32],
    pub hns_address_version: u8,
    pub hns_address_hash: Vec<u8>,
    pub certified_service_credit: U512,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ObjectError {
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error("certificate signers are not strictly sorted and unique")]
    UnsortedSigners,
    #[error("bucket leaves are not strictly sorted by bucket ID")]
    UnsortedBuckets,
    #[error("receipt entries are not sorted by work key and share ID")]
    UnsortedReceiptEntries,
    #[error("parallel receipt vectors have different lengths")]
    ReceiptLengthMismatch,
    #[error("DAG parents are not strictly sorted and unique")]
    UnsortedDagParents,
    #[error("domain tag is not ASCII")]
    NonAsciiDomain,
}

pub trait UnsignedObject {
    const DOMAIN_TAG: &'static str;
    fn encode_unsigned(&self, encoder: &mut Encoder);

    fn object_id(&self) -> Hash256 {
        domain_hash(Self::DOMAIN_TAG, &self.unsigned_bytes())
    }

    fn unsigned_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        self.encode_unsigned(&mut encoder);
        encoder.into_bytes()
    }
}

pub fn domain_hash(domain: &str, body: &[u8]) -> Hash256 {
    assert!(domain.is_ascii(), "protocol domain tags must be ASCII");
    let mut encoder = Encoder::new();
    encoder.bytes(domain.as_bytes());
    encoder.fixed(body);
    blake2b_256(&[encoder.as_bytes()])
}

pub(crate) fn encode_option<T>(
    encoder: &mut Encoder,
    value: &Option<T>,
    encode: impl FnOnce(&mut Encoder, &T),
) {
    match value {
        None => encoder.u8(0),
        Some(value) => {
            encoder.u8(1);
            encode(encoder, value);
        }
    }
}

pub(crate) fn encode_hashes(encoder: &mut Encoder, values: &[Hash256]) {
    encoder.varint(values.len() as u64);
    for value in values {
        encoder.fixed(value);
    }
}

pub(crate) fn decode_hashes(decoder: &mut Decoder<'_>) -> Result<Vec<Hash256>, CodecError> {
    let count = decoder.length(MAX_OBJECT_HASHES)?;
    (0..count).map(|_| decoder.array()).collect()
}

pub(crate) fn encode_u512s(encoder: &mut Encoder, values: &[U512]) {
    encoder.varint(values.len() as u64);
    for value in values {
        value.encode(encoder);
    }
}

pub(crate) fn decode_u512s(decoder: &mut Decoder<'_>) -> Result<Vec<U512>, CodecError> {
    let count = decoder.length(MAX_OBJECT_HASHES)?;
    (0..count).map(|_| U512::decode(decoder)).collect()
}

impl CanonicalEncode for U256 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.fixed(&self.0);
    }
}

impl CanonicalDecode for U256 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self(decoder.array()?))
    }
}

impl CanonicalEncode for U512 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.fixed(&self.0);
    }
}

impl CanonicalDecode for U512 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self(decoder.array()?))
    }
}

impl CanonicalEncode for SignatureBytes {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.bytes(&self.0);
    }
}

impl CanonicalDecode for SignatureBytes {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self(decoder.bytes(MAX_SIGNATURE_BYTES)?))
    }
}

impl CanonicalEncode for SignerSignature {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.fixed(&self.signer_pubkey);
        self.signature.encode(encoder);
    }
}

impl CanonicalDecode for SignerSignature {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            signer_pubkey: decoder.array()?,
            signature: SignatureBytes::decode(decoder)?,
        })
    }
}

impl CanonicalEncode for SignatureSet {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u16(self.signature_suite);
        encoder.varint(self.signatures.len() as u64);
        for signature in &self.signatures {
            signature.encode(encoder);
        }
    }
}

impl CanonicalDecode for SignatureSet {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let signature_suite = decoder.u16()?;
        let count = decoder.length(MAX_CERTIFICATE_SIGNERS)?;
        let signatures = (0..count)
            .map(|_| SignerSignature::decode(decoder))
            .collect::<Result<Vec<_>, _>>()?;
        let set = Self {
            signature_suite,
            signatures,
        };
        set.validate_order()
            .map_err(|_| CodecError::InvalidField("unsorted certificate signers"))?;
        Ok(set)
    }
}

impl CanonicalEncode for WorkBucketLeaf {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.fixed(&self.bucket_id);
        encoder.fixed(&self.operator_pubkey);
        encoder.u8(self.hns_address_version);
        encoder.bytes(&self.hns_address_hash);
        self.credited_work.encode(encoder);
    }
}

impl CanonicalDecode for WorkBucketLeaf {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            bucket_id: decoder.array()?,
            operator_pubkey: decoder.array()?,
            hns_address_version: decoder.u8()?,
            hns_address_hash: decoder.bytes(MAX_ADDRESS_HASH_BYTES)?,
            credited_work: U512::decode(decoder)?,
        })
    }
}

impl CanonicalEncode for ServiceBucketLeaf {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.fixed(&self.bucket_id);
        encoder.fixed(&self.operator_pubkey);
        encoder.u8(self.hns_address_version);
        encoder.bytes(&self.hns_address_hash);
        self.certified_service_credit.encode(encoder);
    }
}

impl CanonicalDecode for ServiceBucketLeaf {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            bucket_id: decoder.array()?,
            operator_pubkey: decoder.array()?,
            hns_address_version: decoder.u8()?,
            hns_address_hash: decoder.bytes(MAX_ADDRESS_HASH_BYTES)?,
            certified_service_credit: U512::decode(decoder)?,
        })
    }
}

pub(crate) fn validate_bucket_order<T>(
    values: &[T],
    bucket_id: impl Fn(&T) -> &PayoutBucketId,
) -> Result<(), ObjectError> {
    if values
        .windows(2)
        .any(|pair| bucket_id(&pair[0]) >= bucket_id(&pair[1]))
    {
        return Err(ObjectError::UnsortedBuckets);
    }
    Ok(())
}

fn hex_debug(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}
