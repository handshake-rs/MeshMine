use std::sync::Arc;

use meshmine_codec::Encoder;
use meshmine_crypto::verify_object;
use meshmine_gateway::{DurableCaptureConsumer, ForwardedCapture};
use meshmine_hns::Hash256;
use meshmine_storage::{BatchOperation, DurableStore, StorageError};
use meshmine_types::{ED25519_SUITE, SignatureBytes, UnsignedObject};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CORE_CAPTURE_RECEIPT_NAMESPACE: &str = "operator-core-capture-receipt/v1";
pub const CORE_CAPTURE_RECEIPT_CONFLICT_NAMESPACE: &str =
    "operator-core-capture-receipt-conflict/v1";
pub const CORE_CAPTURE_RECEIPT_VERSION: u16 = 1;

/// Core-signed immutable evidence that one gateway work key was admitted
/// durably downstream. The configured operator service accepts receipts only
/// from its pinned Core key and network; canonical self-signing by an arbitrary
/// key is insufficient.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreCaptureReceiptV1 {
    pub version: u16,
    pub network_id: u8,
    pub receipt_id: Hash256,
    pub work_key: Hash256,
    pub downstream_id: Hash256,
    pub core_context_id: Hash256,
    pub admitted_at_ms: u64,
    pub core_receipt_pubkey: [u8; 32],
    pub signature_suite: u16,
    pub core_signature: Vec<u8>,
}

impl UnsignedObject for CoreCaptureReceiptV1 {
    const DOMAIN_TAG: &'static str = "meshmine/operator-core-capture-receipt/v1";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encoder.u16(self.version);
        encoder.u8(self.network_id);
        encoder.fixed(&self.work_key);
        encoder.fixed(&self.downstream_id);
        encoder.fixed(&self.core_context_id);
        encoder.u64(self.admitted_at_ms);
        encoder.fixed(&self.core_receipt_pubkey);
        encoder.u16(self.signature_suite);
    }
}

impl CoreCaptureReceiptV1 {
    /// Build the exact unsigned object that Core must sign. The returned object
    /// is intentionally not importable until `core_signature` is replaced by a
    /// valid signature from the configured Core receipt key.
    pub fn new_unsigned(
        network_id: u8,
        work_key: Hash256,
        downstream_id: Hash256,
        core_context_id: Hash256,
        admitted_at_ms: u64,
        core_receipt_pubkey: [u8; 32],
    ) -> Result<Self, ReceiptError> {
        let mut receipt = Self {
            version: CORE_CAPTURE_RECEIPT_VERSION,
            network_id,
            receipt_id: [0; 32],
            work_key,
            downstream_id,
            core_context_id,
            admitted_at_ms,
            core_receipt_pubkey,
            signature_suite: ED25519_SUITE,
            core_signature: Vec::new(),
        };
        receipt.receipt_id = receipt.object_id();
        receipt.validate_fields()?;
        Ok(receipt)
    }

    pub fn canonical_id(&self) -> Hash256 {
        self.object_id()
    }

    pub fn validate(
        &self,
        expected_network_id: u8,
        expected_core_pubkey: &[u8; 32],
    ) -> Result<(), ReceiptError> {
        self.validate_fields()?;
        if self.network_id != expected_network_id
            || &self.core_receipt_pubkey != expected_core_pubkey
        {
            return Err(ReceiptError::UntrustedSigner);
        }
        verify_object(
            &self.core_receipt_pubkey,
            self.signature_suite,
            &SignatureBytes(self.core_signature.clone()),
            self.network_id,
            self,
        )
        .map_err(|_| ReceiptError::Signature)
    }

    fn validate_fields(&self) -> Result<(), ReceiptError> {
        if self.version != CORE_CAPTURE_RECEIPT_VERSION
            || self.work_key == [0; 32]
            || self.downstream_id == [0; 32]
            || self.core_context_id == [0; 32]
            || self.core_receipt_pubkey == [0; 32]
            || self.signature_suite != ED25519_SUITE
            || (!self.core_signature.is_empty() && self.core_signature.len() != 64)
            || self.receipt_id != self.object_id()
        {
            return Err(ReceiptError::InvalidReceipt);
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ReceiptError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("Core capture receipt conflicts with an existing immutable mapping")]
    Conflict,
    #[error("Core capture receipt is malformed or has an invalid canonical identifier")]
    InvalidReceipt,
    #[error("Core capture receipt does not match the pinned network and Core key")]
    UntrustedSigner,
    #[error("Core capture receipt signature verification failed")]
    Signature,
    #[error("Core capture receipt serialization is malformed")]
    Serialization,
}

/// ACK-only consumer used by the continuous gateway service. It cannot create
/// a ShareV2 or infer missing Core context. It succeeds only when another
/// component has already persisted a canonical, pinned-key Core receipt after
/// durable Core admission.
pub struct ReceiptBackedCaptureConsumer {
    store: Arc<dyn DurableStore>,
    expected_network_id: u8,
    expected_core_pubkey: [u8; 32],
}

impl ReceiptBackedCaptureConsumer {
    pub fn new(
        store: Arc<dyn DurableStore>,
        expected_network_id: u8,
        expected_core_pubkey: [u8; 32],
    ) -> Self {
        Self {
            store,
            expected_network_id,
            expected_core_pubkey,
        }
    }

    pub fn record_core_receipt(&self, receipt: &CoreCaptureReceiptV1) -> Result<(), ReceiptError> {
        receipt.validate(self.expected_network_id, &self.expected_core_pubkey)?;
        let key = hex::encode(receipt.work_key);
        let bytes = serde_json::to_vec(receipt).map_err(|_| ReceiptError::Serialization)?;
        if self
            .store
            .put_if_absent(CORE_CAPTURE_RECEIPT_NAMESPACE, &key, &bytes)?
        {
            return Ok(());
        }
        match self.store.get(CORE_CAPTURE_RECEIPT_NAMESPACE, &key)? {
            Some(existing) if existing == bytes => Ok(()),
            Some(_) => {
                self.store.apply_batch(&[BatchOperation::put(
                    CORE_CAPTURE_RECEIPT_CONFLICT_NAMESPACE,
                    format!("{key}/{}", hex::encode(receipt.receipt_id)),
                    bytes,
                )])?;
                Err(ReceiptError::Conflict)
            }
            None => Err(ReceiptError::Conflict),
        }
    }

    pub fn receipt(
        &self,
        work_key: &Hash256,
    ) -> Result<Option<CoreCaptureReceiptV1>, ReceiptError> {
        let Some(bytes) = self
            .store
            .get(CORE_CAPTURE_RECEIPT_NAMESPACE, &hex::encode(work_key))?
        else {
            return Ok(None);
        };
        let receipt: CoreCaptureReceiptV1 =
            serde_json::from_slice(&bytes).map_err(|_| ReceiptError::Serialization)?;
        receipt.validate(self.expected_network_id, &self.expected_core_pubkey)?;
        if receipt.work_key != *work_key {
            return Err(ReceiptError::InvalidReceipt);
        }
        Ok(Some(receipt))
    }
}

impl DurableCaptureConsumer for ReceiptBackedCaptureConsumer {
    fn admit_capture(&mut self, capture: &ForwardedCapture) -> Result<Hash256, String> {
        self.receipt(&capture.work_key())
            .map_err(|error| error.to_string())?
            .map(|receipt| receipt.downstream_id)
            .ok_or_else(|| "canonical Core capture receipt is not durable yet".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use meshmine_crypto::sign_object;
    use meshmine_storage::MemoryStore;

    fn signed_receipt(
        key: &SigningKey,
        work_key: Hash256,
        downstream_id: Hash256,
    ) -> CoreCaptureReceiptV1 {
        let mut receipt = CoreCaptureReceiptV1::new_unsigned(
            2,
            work_key,
            downstream_id,
            [3; 32],
            4,
            key.verifying_key().to_bytes(),
        )
        .unwrap();
        receipt.core_signature = sign_object(key, receipt.network_id, &receipt).0;
        receipt
    }

    #[test]
    fn receipt_mapping_is_idempotent_and_conflicts_fail_closed() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let store: Arc<dyn DurableStore> = Arc::new(MemoryStore::default());
        let consumer = ReceiptBackedCaptureConsumer::new(store, 2, key.verifying_key().to_bytes());
        let receipt = signed_receipt(&key, [1; 32], [2; 32]);
        consumer.record_core_receipt(&receipt).unwrap();
        consumer.record_core_receipt(&receipt).unwrap();
        assert_eq!(consumer.receipt(&[1; 32]).unwrap(), Some(receipt));
        let conflict = signed_receipt(&key, [1; 32], [4; 32]);
        assert!(matches!(
            consumer.record_core_receipt(&conflict),
            Err(ReceiptError::Conflict)
        ));
    }

    #[test]
    fn canonical_receipt_rejects_malformed_signature_length() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut receipt = signed_receipt(&key, [1; 32], [2; 32]);
        receipt.core_signature.pop();
        assert!(matches!(
            receipt.validate(2, &key.verifying_key().to_bytes()),
            Err(ReceiptError::InvalidReceipt)
        ));
    }

    #[test]
    fn canonical_receipt_rejects_tampering_and_untrusted_keys() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let other = SigningKey::from_bytes(&[8; 32]);
        let mut receipt = signed_receipt(&key, [1; 32], [2; 32]);
        assert!(matches!(
            receipt.validate(2, &other.verifying_key().to_bytes()),
            Err(ReceiptError::UntrustedSigner)
        ));
        receipt.downstream_id = [5; 32];
        assert!(matches!(
            receipt.validate(2, &key.verifying_key().to_bytes()),
            Err(ReceiptError::InvalidReceipt)
        ));
    }
}
