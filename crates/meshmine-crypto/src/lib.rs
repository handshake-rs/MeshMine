//! Algorithm-agile signing boundary for the Core v2 test profile.
//!
//! Suite 1 is Ed25519. Signatures cover a context-bound hash containing the
//! object domain, network, protocol version, and completed unsigned object ID.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use meshmine_codec::Encoder;
use meshmine_hns::Hash256;
use meshmine_storage::{DurableInvariantError, DurableSignGuard};
use meshmine_types::{
    CORE_V2, ED25519_SUITE, SignatureBytes, SignatureSet, SignerSignature, UnsignedObject,
    domain_hash,
};
use thiserror::Error;

const SIGNATURE_CONTEXT: &str = "meshmine/signature-context/v2";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("unsupported signature suite {0}")]
    UnsupportedSuite(u16),
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    #[error("invalid Ed25519 signature length: expected 64, got {0}")]
    InvalidSignatureLength(usize),
    #[error("Ed25519 signature verification failed")]
    VerificationFailed,
    #[error("certificate signer list contains duplicate public keys")]
    DuplicateSigner,
    #[error("durable signing guard rejected the signature: {0}")]
    DurableSigning(#[from] DurableInvariantError),
}

pub fn signature_message<T: UnsignedObject>(network_id: u8, object: &T) -> Hash256 {
    let mut encoder = Encoder::new();
    encoder.u16(CORE_V2);
    encoder.u8(network_id);
    encoder.bytes(T::DOMAIN_TAG.as_bytes());
    encoder.fixed(&object.object_id());
    domain_hash(SIGNATURE_CONTEXT, encoder.as_bytes())
}

pub fn sign_object<T: UnsignedObject>(
    signing_key: &SigningKey,
    network_id: u8,
    object: &T,
) -> SignatureBytes {
    let signature = signing_key.sign(&signature_message(network_id, object));
    SignatureBytes(signature.to_bytes().to_vec())
}

pub fn verify_object<T: UnsignedObject>(
    verifying_key: &[u8; 32],
    signature_suite: u16,
    signature: &SignatureBytes,
    network_id: u8,
    object: &T,
) -> Result<(), CryptoError> {
    verify_message(
        verifying_key,
        signature_suite,
        signature,
        &signature_message(network_id, object),
    )
}

pub fn sign_certificate<T: UnsignedObject>(
    signing_key: &SigningKey,
    network_id: u8,
    object: &T,
) -> SignerSignature {
    SignerSignature {
        signer_pubkey: signing_key.verifying_key().to_bytes(),
        signature: sign_object(signing_key, network_id, object),
    }
}

/// Reserve the certificate slot durably before producing signature bytes.
/// Use this for receipt batches, session closes, snapshots, payout plans, and
/// any other role where MM-0001 permits one object per logical sequence.
pub fn guarded_sign_certificate<T: UnsignedObject>(
    signing_key: &SigningKey,
    network_id: u8,
    object: &T,
    guard: &DurableSignGuard<'_>,
    role: &str,
    scope: &[u8],
    sequence: u64,
) -> Result<SignerSignature, CryptoError> {
    guard.authorize(role, scope, sequence, &object.object_id())?;
    Ok(sign_certificate(signing_key, network_id, object))
}

pub fn assemble_ed25519_set(
    mut signatures: Vec<SignerSignature>,
) -> Result<SignatureSet, CryptoError> {
    signatures.sort_by_key(|entry| entry.signer_pubkey);
    if signatures
        .windows(2)
        .any(|pair| pair[0].signer_pubkey == pair[1].signer_pubkey)
    {
        return Err(CryptoError::DuplicateSigner);
    }
    Ok(SignatureSet {
        signature_suite: ED25519_SUITE,
        signatures,
    })
}

pub fn verify_certificate<T: UnsignedObject>(
    signer_set: &SignatureSet,
    network_id: u8,
    object: &T,
) -> Result<(), CryptoError> {
    if signer_set.signature_suite != ED25519_SUITE {
        return Err(CryptoError::UnsupportedSuite(signer_set.signature_suite));
    }
    signer_set
        .validate_order()
        .map_err(|_| CryptoError::DuplicateSigner)?;
    let message = signature_message(network_id, object);
    for entry in &signer_set.signatures {
        verify_message(
            &entry.signer_pubkey,
            signer_set.signature_suite,
            &entry.signature,
            &message,
        )?;
    }
    Ok(())
}

fn verify_message(
    verifying_key: &[u8; 32],
    signature_suite: u16,
    signature: &SignatureBytes,
    message: &[u8],
) -> Result<(), CryptoError> {
    if signature_suite != ED25519_SUITE {
        return Err(CryptoError::UnsupportedSuite(signature_suite));
    }
    let verifying_key =
        VerifyingKey::from_bytes(verifying_key).map_err(|_| CryptoError::InvalidPublicKey)?;
    let signature_bytes: [u8; 64] = signature
        .0
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidSignatureLength(signature.0.len()))?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(message, &signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use meshmine_storage::{DurableInvariantError, DurableSignGuard, MemoryStore};
    use meshmine_types::{OperatorRecordV2, SignatureBytes};

    use super::*;

    fn operator() -> OperatorRecordV2 {
        OperatorRecordV2 {
            protocol_version: CORE_V2,
            network_id: 2,
            operator_pubkey: [7; 32],
            sequence: 1,
            supported_features: 0,
            payout_bucket_ids: vec![],
            contact_metadata_hash: None,
            signature_suite: ED25519_SUITE,
            signature: SignatureBytes::empty(),
        }
    }

    #[test]
    fn signs_context_bound_object_id() {
        let key = SigningKey::from_bytes(&[42; 32]);
        let mut object = operator();
        let signature = sign_object(&key, object.network_id, &object);
        verify_object(
            &key.verifying_key().to_bytes(),
            ED25519_SUITE,
            &signature,
            object.network_id,
            &object,
        )
        .unwrap();

        object.sequence += 1;
        assert!(
            verify_object(
                &key.verifying_key().to_bytes(),
                ED25519_SUITE,
                &signature,
                object.network_id,
                &object,
            )
            .is_err()
        );
    }

    #[test]
    fn certificate_set_is_sorted_and_verified() {
        let object = operator();
        let first = SigningKey::from_bytes(&[1; 32]);
        let second = SigningKey::from_bytes(&[2; 32]);
        let set = assemble_ed25519_set(vec![
            sign_certificate(&second, object.network_id, &object),
            sign_certificate(&first, object.network_id, &object),
        ])
        .unwrap();
        verify_certificate(&set, object.network_id, &object).unwrap();
    }

    #[test]
    fn guarded_signing_is_idempotent_but_rejects_sequence_equivocation() {
        let store = MemoryStore::default();
        let guard = DurableSignGuard::new(&store);
        let key = SigningKey::from_bytes(&[4; 32]);
        let first = operator();
        let signature = guarded_sign_certificate(
            &key,
            first.network_id,
            &first,
            &guard,
            "receipt",
            &[9; 32],
            1,
        )
        .unwrap();
        let repeated = guarded_sign_certificate(
            &key,
            first.network_id,
            &first,
            &guard,
            "receipt",
            &[9; 32],
            1,
        )
        .unwrap();
        assert_eq!(signature, repeated);

        let mut conflicting = first;
        conflicting.sequence = 2;
        assert!(matches!(
            guarded_sign_certificate(
                &key,
                conflicting.network_id,
                &conflicting,
                &guard,
                "receipt",
                &[9; 32],
                1,
            ),
            Err(CryptoError::DurableSigning(
                DurableInvariantError::ConflictingSignature
            ))
        ));
    }
}
