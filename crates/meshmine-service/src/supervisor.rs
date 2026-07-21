use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SERVICE_SCHEMA_VERSION: u16 = 3;
pub const SERVICE_PROFILE: &str = "meshmine-operator-v9";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceMode {
    Bootstrapping,
    Mining,
    Degraded,
    Fallback,
    Draining,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealthReason {
    None,
    NoCurrentJob,
    JobNotStarted,
    JobExpired,
    CaptureBacklog,
    GatewayUnavailable,
    ReceiptStoreUnavailable,
    CredentialUnavailable,
    CoreLinkUnavailable,
    AssignmentDrainPending,
    AuthorizationFailureLimit,
    OperatorShutdown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupervisorPolicy {
    pub unhealthy_samples_before_fallback: u32,
    pub healthy_samples_before_restore: u32,
    pub minimum_fallback_hold_ms: u64,
    pub capture_backlog_soft_limit: usize,
    pub capture_backlog_hard_limit: usize,
}

impl Default for SupervisorPolicy {
    fn default() -> Self {
        Self {
            unhealthy_samples_before_fallback: 3,
            healthy_samples_before_restore: 5,
            minimum_fallback_hold_ms: 15_000,
            capture_backlog_soft_limit: 10_000,
            capture_backlog_hard_limit: 90_000,
        }
    }
}

impl SupervisorPolicy {
    pub fn validate(self) -> Result<Self, SupervisorError> {
        if self.unhealthy_samples_before_fallback == 0
            || self.healthy_samples_before_restore == 0
            || self.capture_backlog_soft_limit == 0
            || self.capture_backlog_hard_limit <= self.capture_backlog_soft_limit
        {
            return Err(SupervisorError::InvalidPolicy);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthSample {
    pub now_ms: u64,
    pub gateway_available: bool,
    pub receipt_store_available: bool,
    pub credentials_available: bool,
    pub core_link_available: bool,
    pub drain_pending: bool,
    pub authorization_failure_limit: bool,
    pub current_job_id: Option<String>,
    pub job_issued_ms: Option<u64>,
    pub assignment_end_ms: Option<u64>,
    pub pending_captures: usize,
    pub shutdown_requested: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorSnapshot {
    pub schema_version: u16,
    pub profile: String,
    pub mode: ServiceMode,
    pub reason: HealthReason,
    pub transition_sequence: u64,
    pub changed_at_ms: u64,
    pub sampled_at_ms: u64,
    pub consecutive_healthy: u32,
    pub consecutive_unhealthy: u32,
    pub current_job_id: Option<String>,
    pub pending_captures: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModeTransition {
    pub from: ServiceMode,
    pub to: ServiceMode,
    pub reason: HealthReason,
    pub sequence: u64,
    pub changed_at_ms: u64,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SupervisorError {
    #[error("operator supervisor policy is invalid")]
    InvalidPolicy,
}

pub struct Supervisor {
    policy: SupervisorPolicy,
    snapshot: SupervisorSnapshot,
}

impl Supervisor {
    pub fn new(policy: SupervisorPolicy, now_ms: u64) -> Result<Self, SupervisorError> {
        let policy = policy.validate()?;
        Ok(Self {
            policy,
            snapshot: SupervisorSnapshot {
                schema_version: SERVICE_SCHEMA_VERSION,
                profile: SERVICE_PROFILE.to_owned(),
                mode: ServiceMode::Bootstrapping,
                reason: HealthReason::NoCurrentJob,
                transition_sequence: 0,
                changed_at_ms: now_ms,
                sampled_at_ms: now_ms,
                consecutive_healthy: 0,
                consecutive_unhealthy: 0,
                current_job_id: None,
                pending_captures: 0,
            },
        })
    }

    pub fn snapshot(&self) -> &SupervisorSnapshot {
        &self.snapshot
    }

    pub fn begin_draining(&mut self, now_ms: u64) -> Option<ModeTransition> {
        self.transition(
            ServiceMode::Draining,
            HealthReason::OperatorShutdown,
            now_ms,
        )
    }

    pub fn stop(&mut self, now_ms: u64) -> Option<ModeTransition> {
        self.transition(ServiceMode::Stopped, HealthReason::OperatorShutdown, now_ms)
    }

    pub fn sample(&mut self, sample: HealthSample) -> Option<ModeTransition> {
        self.snapshot.sampled_at_ms = sample.now_ms;
        self.snapshot.current_job_id = sample.current_job_id.clone();
        self.snapshot.pending_captures = sample.pending_captures;

        if sample.shutdown_requested {
            return self.begin_draining(sample.now_ms);
        }
        if self.snapshot.mode == ServiceMode::Stopped {
            return None;
        }
        if sample.drain_pending {
            return self.transition(
                ServiceMode::Draining,
                HealthReason::AssignmentDrainPending,
                sample.now_ms,
            );
        }
        if self.snapshot.mode == ServiceMode::Draining
            && self.snapshot.reason == HealthReason::OperatorShutdown
        {
            return None;
        }

        let critical_reason = critical_reason(&sample, &self.policy);
        let healthy = critical_reason == HealthReason::None;
        if healthy {
            self.snapshot.consecutive_healthy = self.snapshot.consecutive_healthy.saturating_add(1);
            self.snapshot.consecutive_unhealthy = 0;
        } else {
            self.snapshot.consecutive_unhealthy =
                self.snapshot.consecutive_unhealthy.saturating_add(1);
            self.snapshot.consecutive_healthy = 0;
        }

        match self.snapshot.mode {
            ServiceMode::Bootstrapping => {
                if healthy {
                    self.transition(ServiceMode::Mining, HealthReason::None, sample.now_ms)
                } else if self.snapshot.consecutive_unhealthy
                    >= self.policy.unhealthy_samples_before_fallback
                {
                    self.transition(ServiceMode::Fallback, critical_reason, sample.now_ms)
                } else {
                    self.snapshot.reason = critical_reason;
                    None
                }
            }
            ServiceMode::Mining | ServiceMode::Degraded => {
                if !healthy
                    && self.snapshot.consecutive_unhealthy
                        >= self.policy.unhealthy_samples_before_fallback
                {
                    self.transition(ServiceMode::Fallback, critical_reason, sample.now_ms)
                } else if healthy
                    && sample.pending_captures >= self.policy.capture_backlog_soft_limit
                {
                    self.transition(
                        ServiceMode::Degraded,
                        HealthReason::CaptureBacklog,
                        sample.now_ms,
                    )
                } else if healthy && self.snapshot.mode == ServiceMode::Degraded {
                    self.transition(ServiceMode::Mining, HealthReason::None, sample.now_ms)
                } else {
                    self.snapshot.reason = if healthy {
                        HealthReason::None
                    } else {
                        critical_reason
                    };
                    None
                }
            }
            ServiceMode::Fallback => {
                let held_ms = sample.now_ms.saturating_sub(self.snapshot.changed_at_ms);
                if healthy
                    && self.snapshot.consecutive_healthy
                        >= self.policy.healthy_samples_before_restore
                    && held_ms >= self.policy.minimum_fallback_hold_ms
                {
                    self.transition(ServiceMode::Mining, HealthReason::None, sample.now_ms)
                } else {
                    if !healthy {
                        self.snapshot.reason = critical_reason;
                    }
                    None
                }
            }
            ServiceMode::Draining => {
                if healthy
                    && self.snapshot.consecutive_healthy
                        >= self.policy.healthy_samples_before_restore
                {
                    self.transition(ServiceMode::Mining, HealthReason::None, sample.now_ms)
                } else if !healthy
                    && self.snapshot.consecutive_unhealthy
                        >= self.policy.unhealthy_samples_before_fallback
                {
                    self.transition(ServiceMode::Fallback, critical_reason, sample.now_ms)
                } else {
                    self.snapshot.reason = if healthy {
                        HealthReason::None
                    } else {
                        critical_reason
                    };
                    None
                }
            }
            ServiceMode::Stopped => None,
        }
    }

    fn transition(
        &mut self,
        mode: ServiceMode,
        reason: HealthReason,
        now_ms: u64,
    ) -> Option<ModeTransition> {
        if self.snapshot.mode == mode && self.snapshot.reason == reason {
            return None;
        }
        let from = self.snapshot.mode;
        self.snapshot.mode = mode;
        self.snapshot.reason = reason;
        self.snapshot.changed_at_ms = now_ms;
        self.snapshot.transition_sequence = self.snapshot.transition_sequence.saturating_add(1);
        Some(ModeTransition {
            from,
            to: mode,
            reason,
            sequence: self.snapshot.transition_sequence,
            changed_at_ms: now_ms,
        })
    }
}

fn critical_reason(sample: &HealthSample, policy: &SupervisorPolicy) -> HealthReason {
    if sample.authorization_failure_limit {
        return HealthReason::AuthorizationFailureLimit;
    }
    if !sample.gateway_available {
        return HealthReason::GatewayUnavailable;
    }
    if !sample.receipt_store_available {
        return HealthReason::ReceiptStoreUnavailable;
    }
    if !sample.credentials_available {
        return HealthReason::CredentialUnavailable;
    }
    if !sample.core_link_available {
        return HealthReason::CoreLinkUnavailable;
    }
    if sample.pending_captures >= policy.capture_backlog_hard_limit {
        return HealthReason::CaptureBacklog;
    }
    let Some(_) = sample.current_job_id else {
        return HealthReason::NoCurrentJob;
    };
    let Some(issued_ms) = sample.job_issued_ms else {
        return HealthReason::NoCurrentJob;
    };
    let Some(assignment_end_ms) = sample.assignment_end_ms else {
        return HealthReason::NoCurrentJob;
    };
    if sample.now_ms < issued_ms {
        return HealthReason::JobNotStarted;
    }
    if sample.now_ms > assignment_end_ms {
        return HealthReason::JobExpired;
    }
    HealthReason::None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy(now_ms: u64) -> HealthSample {
        HealthSample {
            now_ms,
            gateway_available: true,
            receipt_store_available: true,
            credentials_available: true,
            core_link_available: true,
            drain_pending: false,
            authorization_failure_limit: false,
            current_job_id: Some("job".to_owned()),
            job_issued_ms: Some(1),
            assignment_end_ms: Some(1_000_000),
            pending_captures: 0,
            shutdown_requested: false,
        }
    }

    #[test]
    fn fallback_requires_consecutive_failure_and_recovery_hysteresis() {
        let policy = SupervisorPolicy {
            unhealthy_samples_before_fallback: 2,
            healthy_samples_before_restore: 2,
            minimum_fallback_hold_ms: 10,
            capture_backlog_soft_limit: 10,
            capture_backlog_hard_limit: 20,
        };
        let mut supervisor = Supervisor::new(policy, 0).unwrap();
        assert_eq!(
            supervisor.sample(healthy(1)).unwrap().to,
            ServiceMode::Mining
        );
        let mut bad = healthy(2);
        bad.current_job_id = None;
        assert!(supervisor.sample(bad.clone()).is_none());
        bad.now_ms = 3;
        assert_eq!(supervisor.sample(bad).unwrap().to, ServiceMode::Fallback);
        assert!(supervisor.sample(healthy(8)).is_none());
        assert!(supervisor.sample(healthy(12)).is_none());
        assert_eq!(
            supervisor.sample(healthy(14)).unwrap().to,
            ServiceMode::Mining
        );
    }

    #[test]
    fn core_link_loss_falls_back_and_recovers_with_hysteresis() {
        let policy = SupervisorPolicy {
            unhealthy_samples_before_fallback: 2,
            healthy_samples_before_restore: 2,
            minimum_fallback_hold_ms: 5,
            capture_backlog_soft_limit: 10,
            capture_backlog_hard_limit: 20,
        };
        let mut supervisor = Supervisor::new(policy, 0).unwrap();
        assert_eq!(
            supervisor.sample(healthy(1)).unwrap().to,
            ServiceMode::Mining
        );
        let mut disconnected = healthy(2);
        disconnected.core_link_available = false;
        assert!(supervisor.sample(disconnected.clone()).is_none());
        disconnected.now_ms = 3;
        let transition = supervisor.sample(disconnected).unwrap();
        assert_eq!(transition.to, ServiceMode::Fallback);
        assert_eq!(transition.reason, HealthReason::CoreLinkUnavailable);
        assert!(supervisor.sample(healthy(7)).is_none());
        assert_eq!(
            supervisor.sample(healthy(9)).unwrap().to,
            ServiceMode::Mining
        );
    }

    #[test]
    fn signed_assignment_drain_enters_draining_then_recovers() {
        let policy = SupervisorPolicy {
            unhealthy_samples_before_fallback: 1,
            healthy_samples_before_restore: 1,
            minimum_fallback_hold_ms: 0,
            capture_backlog_soft_limit: 10,
            capture_backlog_hard_limit: 20,
        };
        let mut supervisor = Supervisor::new(policy, 0).unwrap();
        assert_eq!(
            supervisor.sample(healthy(1)).unwrap().to,
            ServiceMode::Mining
        );
        let mut draining = healthy(2);
        draining.drain_pending = true;
        let transition = supervisor.sample(draining).unwrap();
        assert_eq!(transition.to, ServiceMode::Draining);
        assert_eq!(transition.reason, HealthReason::AssignmentDrainPending);
        assert_eq!(
            supervisor.sample(healthy(3)).unwrap().to,
            ServiceMode::Mining
        );
    }

    #[test]
    fn hard_backlog_triggers_fallback_while_soft_backlog_degrades() {
        let policy = SupervisorPolicy {
            unhealthy_samples_before_fallback: 1,
            healthy_samples_before_restore: 1,
            minimum_fallback_hold_ms: 0,
            capture_backlog_soft_limit: 10,
            capture_backlog_hard_limit: 20,
        };
        let mut supervisor = Supervisor::new(policy, 0).unwrap();
        assert_eq!(
            supervisor.sample(healthy(1)).unwrap().to,
            ServiceMode::Mining
        );
        let mut soft = healthy(2);
        soft.pending_captures = 10;
        assert_eq!(supervisor.sample(soft).unwrap().to, ServiceMode::Degraded);
        let mut hard = healthy(3);
        hard.pending_captures = 20;
        assert_eq!(supervisor.sample(hard).unwrap().to, ServiceMode::Fallback);
    }
}
