use std::sync::Arc;

use meshmine_storage::{BatchOperation, DurableStore, StorageError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{HealthReason, ModeTransition, ServiceMode};

pub const SERVICE_EVENT_NAMESPACE: &str = "operator-event/v1";
pub const SERVICE_EVENT_HEAD_NAMESPACE: &str = "operator-event-head/v1";
pub const MAX_SERVICE_EVENT_CAPACITY: usize = 100_000;
const SERVICE_EVENT_HEAD_KEY: &str = "next";
const MAX_READ_RETRIES: usize = 4;
const MAX_APPEND_RETRIES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEventRecord {
    pub sequence: u64,
    pub observed_at_ms: u64,
    pub kind: String,
    pub message: String,
    pub from_mode: Option<ServiceMode>,
    pub to_mode: Option<ServiceMode>,
    pub reason: Option<HealthReason>,
}

#[derive(Debug, Error)]
pub enum JournalError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("operator event journal head is malformed")]
    CorruptHead,
    #[error("operator event journal sequence exhausted")]
    SequenceExhausted,
    #[error("operator event journal record is missing or malformed")]
    CorruptRecord,
    #[error("operator event journal capacity is outside its supported bound")]
    InvalidCapacity,
    #[error("operator event journal record exceeds its bounded schema")]
    RecordTooLarge,
    #[error("operator event journal changed continuously during a bounded read")]
    ConcurrentMutation,
}

pub struct ServiceEventJournal {
    store: Arc<dyn DurableStore>,
    capacity: usize,
}

impl ServiceEventJournal {
    pub fn new(store: Arc<dyn DurableStore>, capacity: usize) -> Result<Self, JournalError> {
        if capacity == 0 || capacity > MAX_SERVICE_EVENT_CAPACITY {
            return Err(JournalError::InvalidCapacity);
        }
        Ok(Self { store, capacity })
    }

    pub fn append(
        &self,
        observed_at_ms: u64,
        kind: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<ServiceEventRecord, JournalError> {
        self.append_record(ServiceEventRecord {
            sequence: 0,
            observed_at_ms,
            kind: kind.into(),
            message: message.into(),
            from_mode: None,
            to_mode: None,
            reason: None,
        })
    }

    pub fn append_transition(
        &self,
        transition: &ModeTransition,
    ) -> Result<ServiceEventRecord, JournalError> {
        self.append_record(ServiceEventRecord {
            sequence: 0,
            observed_at_ms: transition.changed_at_ms,
            kind: "mode-transition".to_owned(),
            message: format!(
                "operator mode changed from {:?} to {:?}: {:?}",
                transition.from, transition.to, transition.reason
            ),
            from_mode: Some(transition.from),
            to_mode: Some(transition.to),
            reason: Some(transition.reason),
        })
    }

    /// Read the newest bounded records without scanning the complete journal.
    /// Appends can race with dashboard reads, so a changed head causes a bounded
    /// retry instead of reporting a transient oldest-record deletion as
    /// corruption.
    pub fn recent(&self, maximum: usize) -> Result<Vec<ServiceEventRecord>, JournalError> {
        let maximum = maximum.min(self.capacity);
        if maximum == 0 {
            return Ok(Vec::new());
        }
        for _ in 0..MAX_READ_RETRIES {
            let head_before = self.read_head()?;
            let start = head_before.saturating_sub(maximum as u64);
            let mut events = Vec::with_capacity(usize::try_from(head_before - start).unwrap_or(0));
            let mut transient_missing = false;
            for sequence in start..head_before {
                let Some(bytes) = self
                    .store
                    .get(SERVICE_EVENT_NAMESPACE, &format!("{sequence:020}"))?
                else {
                    transient_missing = true;
                    break;
                };
                let event = serde_json::from_slice::<ServiceEventRecord>(&bytes)
                    .map_err(|_| JournalError::CorruptRecord)?;
                if event.sequence != sequence {
                    return Err(JournalError::CorruptRecord);
                }
                events.push(event);
            }
            let head_after = self.read_head()?;
            if head_before == head_after && !transient_missing {
                return Ok(events);
            }
        }
        Err(JournalError::ConcurrentMutation)
    }

    fn read_head(&self) -> Result<u64, JournalError> {
        match self
            .store
            .get(SERVICE_EVENT_HEAD_NAMESPACE, SERVICE_EVENT_HEAD_KEY)?
        {
            None => Ok(0),
            Some(bytes) => decode_u64(&bytes),
        }
    }

    fn append_record(
        &self,
        mut record: ServiceEventRecord,
    ) -> Result<ServiceEventRecord, JournalError> {
        if record.kind.is_empty() || record.kind.len() > 64 || record.message.len() > 4_096 {
            return Err(JournalError::RecordTooLarge);
        }
        for _ in 0..MAX_APPEND_RETRIES {
            let current = self
                .store
                .get(SERVICE_EVENT_HEAD_NAMESPACE, SERVICE_EVENT_HEAD_KEY)?;
            let sequence = match current.as_deref() {
                None => 0,
                Some(bytes) => decode_u64(bytes)?,
            };
            let next = sequence
                .checked_add(1)
                .ok_or(JournalError::SequenceExhausted)?;
            record.sequence = sequence;
            let bytes = serde_json::to_vec(&record).map_err(|_| JournalError::CorruptRecord)?;
            if bytes.len() > 64 * 1024 {
                return Err(JournalError::RecordTooLarge);
            }
            let mut operations = vec![
                BatchOperation::put(SERVICE_EVENT_NAMESPACE, format!("{sequence:020}"), bytes),
                BatchOperation::put(
                    SERVICE_EVENT_HEAD_NAMESPACE,
                    SERVICE_EVENT_HEAD_KEY,
                    next.to_le_bytes().to_vec(),
                ),
            ];
            if sequence >= self.capacity as u64 {
                let oldest = sequence - self.capacity as u64;
                operations.push(BatchOperation::delete(
                    SERVICE_EVENT_NAMESPACE,
                    format!("{oldest:020}"),
                ));
            }
            if self.store.apply_batch_if(
                SERVICE_EVENT_HEAD_NAMESPACE,
                SERVICE_EVENT_HEAD_KEY,
                current.as_deref(),
                &operations,
            )? {
                return Ok(record);
            }
        }
        Err(JournalError::ConcurrentMutation)
    }
}

fn decode_u64(bytes: &[u8]) -> Result<u64, JournalError> {
    Ok(u64::from_le_bytes(
        bytes.try_into().map_err(|_| JournalError::CorruptHead)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshmine_storage::MemoryStore;

    #[test]
    fn journal_retains_only_the_newest_capacity() {
        let store: Arc<dyn DurableStore> = Arc::new(MemoryStore::default());
        let journal = ServiceEventJournal::new(store, 3).unwrap();
        for sequence in 0..5 {
            journal
                .append(sequence, "test", sequence.to_string())
                .unwrap();
        }
        let events = journal.recent(10).unwrap();
        assert_eq!(
            events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
    }

    #[test]
    fn zero_recent_limit_is_empty() {
        let store: Arc<dyn DurableStore> = Arc::new(MemoryStore::default());
        let journal = ServiceEventJournal::new(store, 3).unwrap();
        journal.append(1, "test", "one").unwrap();
        assert!(journal.recent(0).unwrap().is_empty());
    }
}
