//! Explicit, idempotent MM-0001 lifecycle transition guards.

use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyState {
    LocalDraft,
    HsdValidated,
    ErasurePublished,
    AvailabilityCertified,
    Active,
    Expired,
    Pruned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaskSessionState {
    SelectingCommittee,
    MpcSetup,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareState {
    Received,
    SyntaxValid,
    PowValid,
    BodyAvailable,
    DedupValid,
    PendingReceipt,
    Accepted,
    Settled,
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayoutState {
    AccumulatingWork,
    SnapshotClosed,
    WaitingForEntropy,
    PlanReady,
    Payable,
    IncludedInHnsBlock,
    Canonical,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("invalid or unsafe MM-0001 state transition")]
pub struct TransitionError;

impl BodyState {
    pub fn transition(self, next: Self) -> Result<Self, TransitionError> {
        if self == next
            || matches!(
                (self, next),
                (Self::LocalDraft, Self::HsdValidated)
                    | (Self::HsdValidated, Self::ErasurePublished)
                    | (Self::ErasurePublished, Self::AvailabilityCertified)
                    | (Self::AvailabilityCertified, Self::Active)
                    | (Self::Active, Self::Expired)
                    | (Self::Expired, Self::Pruned)
            )
        {
            Ok(next)
        } else {
            Err(TransitionError)
        }
    }
}

impl MaskSessionState {
    pub fn transition(
        self,
        next: Self,
        accepted_shares_exist: bool,
    ) -> Result<Self, TransitionError> {
        if self == next {
            return Ok(next);
        }
        let normal = matches!(
            (self, next),
            (Self::SelectingCommittee, Self::MpcSetup)
                | (Self::MpcSetup, Self::MaskCommitted)
                | (Self::MaskCommitted, Self::Assigning)
                | (Self::Assigning, Self::SubmissionGrace)
                | (Self::SubmissionGrace, Self::ReceiptFinalizing)
                | (Self::ReceiptFinalizing, Self::Opening)
                | (Self::Opening, Self::Opened)
                | (Self::Opened, Self::Closed)
                | (Self::TimedRecovery, Self::Opened)
                | (Self::TimedRecovery, Self::FailedThreshold)
        );
        let pre_open_abort = matches!(
            self,
            Self::SelectingCommittee
                | Self::MpcSetup
                | Self::MaskCommitted
                | Self::Assigning
                | Self::SubmissionGrace
                | Self::ReceiptFinalizing
                | Self::Opening
        ) && next == Self::Aborted;
        let aborted_recovery = self == Self::Aborted
            && ((accepted_shares_exist && next == Self::TimedRecovery)
                || (!accepted_shares_exist && next == Self::Closed));
        if normal || pre_open_abort || aborted_recovery {
            Ok(next)
        } else {
            Err(TransitionError)
        }
    }
}

impl ShareState {
    pub fn transition(self, next: Self) -> Result<Self, TransitionError> {
        if self == next {
            return Ok(next);
        }
        let normal = matches!(
            (self, next),
            (Self::Received, Self::SyntaxValid)
                | (Self::SyntaxValid, Self::PowValid)
                | (Self::PowValid, Self::BodyAvailable)
                | (Self::BodyAvailable, Self::DedupValid)
                | (Self::DedupValid, Self::PendingReceipt)
                | (Self::PendingReceipt, Self::Accepted)
                | (Self::Accepted, Self::Settled)
        );
        let rejection = self != Self::Settled && self != Self::Rejected && next == Self::Rejected;
        if normal || rejection {
            Ok(next)
        } else {
            Err(TransitionError)
        }
    }
}

impl PayoutState {
    pub fn transition(self, next: Self) -> Result<Self, TransitionError> {
        if self == next
            || matches!(
                (self, next),
                (Self::AccumulatingWork, Self::SnapshotClosed)
                    | (Self::SnapshotClosed, Self::WaitingForEntropy)
                    | (Self::WaitingForEntropy, Self::PlanReady)
                    | (Self::PlanReady, Self::Payable)
                    | (Self::Payable, Self::IncludedInHnsBlock)
                    | (Self::IncludedInHnsBlock, Self::Canonical)
                    | (Self::IncludedInHnsBlock, Self::Payable)
                    | (Self::Canonical, Self::Payable)
            )
        {
            Ok(next)
        } else {
            Err(TransitionError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_transitions_are_idempotent_and_skips_are_rejected() {
        for state in [
            BodyState::LocalDraft,
            BodyState::HsdValidated,
            BodyState::ErasurePublished,
            BodyState::AvailabilityCertified,
            BodyState::Active,
            BodyState::Expired,
            BodyState::Pruned,
        ] {
            assert_eq!(state.transition(state), Ok(state));
        }
        assert_eq!(
            BodyState::LocalDraft.transition(BodyState::AvailabilityCertified),
            Err(TransitionError)
        );
        assert_eq!(
            ShareState::Received.transition(ShareState::Accepted),
            Err(TransitionError)
        );
        assert_eq!(
            PayoutState::Canonical.transition(PayoutState::Payable),
            Ok(PayoutState::Payable)
        );
    }

    #[test]
    fn aborted_session_with_accepted_shares_must_enter_timed_recovery() {
        let aborted = MaskSessionState::Assigning
            .transition(MaskSessionState::Aborted, true)
            .unwrap();
        assert_eq!(
            aborted.transition(MaskSessionState::Closed, true),
            Err(TransitionError)
        );
        assert_eq!(
            aborted.transition(MaskSessionState::TimedRecovery, true),
            Ok(MaskSessionState::TimedRecovery)
        );
    }
}
