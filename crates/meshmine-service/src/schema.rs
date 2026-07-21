use std::sync::Arc;

use meshmine_hns::Hash256;
use meshmine_storage::{BatchCondition, BatchOperation, DurableStore, StorageError};
use thiserror::Error;

use crate::{SERVICE_PROFILE, SERVICE_SCHEMA_VERSION};

pub const SERVICE_META_NAMESPACE: &str = "operator-meta/v1";
const SCHEMA_KEY: &str = "schema-version";
const PROFILE_KEY: &str = "profile";
const NETWORK_KEY: &str = "network-id";
const CORE_RECEIPT_KEY: &str = "core-receipt-pubkey";

#[derive(Debug, Error)]
pub enum ServiceSchemaError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("operator service database metadata is incomplete")]
    Incomplete,
    #[error("operator service database schema is malformed")]
    Malformed,
    #[error("operator service database schema {actual} is incompatible with {expected}")]
    IncompatibleSchema { actual: u16, expected: u16 },
    #[error("operator service database profile {actual:?} is incompatible with {expected:?}")]
    IncompatibleProfile { actual: String, expected: String },
    #[error("operator service database is bound to another network or Core receipt key")]
    IncompatibleTrustBinding,
}

/// Initialize an empty operator database or verify the exact durable identity
/// and trust binding of an existing one. Every identity field is committed in
/// one conditional batch so a crash cannot leave a half-identified database.
pub fn initialize_service_store(
    store: &Arc<dyn DurableStore>,
    network_id: u8,
    core_receipt_pubkey: &Hash256,
) -> Result<(), ServiceSchemaError> {
    if *core_receipt_pubkey == [0; 32] {
        return Err(ServiceSchemaError::Malformed);
    }
    let schema = store.get(SERVICE_META_NAMESPACE, SCHEMA_KEY)?;
    let profile = store.get(SERVICE_META_NAMESPACE, PROFILE_KEY)?;
    let network = store.get(SERVICE_META_NAMESPACE, NETWORK_KEY)?;
    let core_key = store.get(SERVICE_META_NAMESPACE, CORE_RECEIPT_KEY)?;
    match (schema, profile, network, core_key) {
        (None, None, None, None) => {
            let conditions = [
                BatchCondition::absent(SERVICE_META_NAMESPACE, SCHEMA_KEY),
                BatchCondition::absent(SERVICE_META_NAMESPACE, PROFILE_KEY),
                BatchCondition::absent(SERVICE_META_NAMESPACE, NETWORK_KEY),
                BatchCondition::absent(SERVICE_META_NAMESPACE, CORE_RECEIPT_KEY),
            ];
            let operations = [
                BatchOperation::put(
                    SERVICE_META_NAMESPACE,
                    SCHEMA_KEY,
                    SERVICE_SCHEMA_VERSION.to_le_bytes().to_vec(),
                ),
                BatchOperation::put(
                    SERVICE_META_NAMESPACE,
                    PROFILE_KEY,
                    SERVICE_PROFILE.as_bytes().to_vec(),
                ),
                BatchOperation::put(SERVICE_META_NAMESPACE, NETWORK_KEY, vec![network_id]),
                BatchOperation::put(
                    SERVICE_META_NAMESPACE,
                    CORE_RECEIPT_KEY,
                    core_receipt_pubkey.to_vec(),
                ),
            ];
            if store.apply_batch_if_all(&conditions, &operations)? {
                return Ok(());
            }
            verify_service_store(store, network_id, core_receipt_pubkey)
        }
        (Some(_), Some(_), Some(_), Some(_)) => {
            verify_service_store(store, network_id, core_receipt_pubkey)
        }
        _ => Err(ServiceSchemaError::Incomplete),
    }
}

pub fn verify_service_store(
    store: &Arc<dyn DurableStore>,
    expected_network_id: u8,
    expected_core_receipt_pubkey: &Hash256,
) -> Result<(), ServiceSchemaError> {
    let schema = store
        .get(SERVICE_META_NAMESPACE, SCHEMA_KEY)?
        .ok_or(ServiceSchemaError::Incomplete)?;
    let profile = store
        .get(SERVICE_META_NAMESPACE, PROFILE_KEY)?
        .ok_or(ServiceSchemaError::Incomplete)?;
    let network = store
        .get(SERVICE_META_NAMESPACE, NETWORK_KEY)?
        .ok_or(ServiceSchemaError::Incomplete)?;
    let core_key = store
        .get(SERVICE_META_NAMESPACE, CORE_RECEIPT_KEY)?
        .ok_or(ServiceSchemaError::Incomplete)?;
    let actual_schema = u16::from_le_bytes(
        schema
            .as_slice()
            .try_into()
            .map_err(|_| ServiceSchemaError::Malformed)?,
    );
    if actual_schema != SERVICE_SCHEMA_VERSION {
        return Err(ServiceSchemaError::IncompatibleSchema {
            actual: actual_schema,
            expected: SERVICE_SCHEMA_VERSION,
        });
    }
    let actual_profile = String::from_utf8(profile).map_err(|_| ServiceSchemaError::Malformed)?;
    if actual_profile != SERVICE_PROFILE {
        return Err(ServiceSchemaError::IncompatibleProfile {
            actual: actual_profile,
            expected: SERVICE_PROFILE.to_owned(),
        });
    }
    if network.as_slice() != [expected_network_id].as_slice()
        || core_key.as_slice() != expected_core_receipt_pubkey.as_slice()
    {
        return Err(ServiceSchemaError::IncompatibleTrustBinding);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshmine_storage::MemoryStore;

    #[test]
    fn schema_identity_is_atomic_idempotent_and_trust_bound() {
        let store: Arc<dyn DurableStore> = Arc::new(MemoryStore::default());
        initialize_service_store(&store, 2, &[7; 32]).unwrap();
        initialize_service_store(&store, 2, &[7; 32]).unwrap();
        verify_service_store(&store, 2, &[7; 32]).unwrap();
        assert!(matches!(
            verify_service_store(&store, 1, &[7; 32]),
            Err(ServiceSchemaError::IncompatibleTrustBinding)
        ));
        assert!(matches!(
            verify_service_store(&store, 2, &[8; 32]),
            Err(ServiceSchemaError::IncompatibleTrustBinding)
        ));
    }

    #[test]
    fn incomplete_identity_fails_closed() {
        let store: Arc<dyn DurableStore> = Arc::new(MemoryStore::default());
        store
            .put(
                SERVICE_META_NAMESPACE,
                SCHEMA_KEY,
                &SERVICE_SCHEMA_VERSION.to_le_bytes(),
            )
            .unwrap();
        assert!(matches!(
            initialize_service_store(&store, 2, &[7; 32]),
            Err(ServiceSchemaError::Incomplete)
        ));
    }
}
