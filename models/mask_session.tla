---- MODULE mask_session ----
EXTENDS Naturals, TLC

VARIABLES phase, boundaryFixed, assignmentIssued, acceptedShares,
          maskOpened, maskMatchesCommitment, acceptedWinner, winnerDetectable

vars == <<phase, boundaryFixed, assignmentIssued, acceptedShares,
          maskOpened, maskMatchesCommitment, acceptedWinner, winnerDetectable>>

Init ==
  /\ phase = "SELECTING_COMMITTEE"
  /\ boundaryFixed = FALSE
  /\ assignmentIssued = FALSE
  /\ acceptedShares = FALSE
  /\ maskOpened = FALSE
  /\ maskMatchesCommitment = TRUE
  /\ acceptedWinner = FALSE
  /\ winnerDetectable = FALSE

Setup ==
  /\ phase = "SELECTING_COMMITTEE"
  /\ phase' = "MPC_SETUP"
  /\ UNCHANGED <<boundaryFixed, assignmentIssued, acceptedShares,
                  maskOpened, maskMatchesCommitment, acceptedWinner, winnerDetectable>>

Commit ==
  /\ phase = "MPC_SETUP"
  /\ phase' = "MASK_COMMITTED"
  /\ UNCHANGED <<boundaryFixed, assignmentIssued, acceptedShares,
                  maskOpened, maskMatchesCommitment, acceptedWinner, winnerDetectable>>

Assign ==
  /\ phase = "MASK_COMMITTED"
  /\ phase' = "ASSIGNING"
  /\ assignmentIssued' = TRUE
  /\ UNCHANGED <<boundaryFixed, acceptedShares, maskOpened,
                  maskMatchesCommitment, acceptedWinner, winnerDetectable>>

AcceptWinner ==
  /\ phase = "ASSIGNING"
  /\ acceptedShares' = TRUE
  /\ acceptedWinner' = TRUE
  /\ UNCHANGED <<phase, boundaryFixed, assignmentIssued, maskOpened,
                  maskMatchesCommitment, winnerDetectable>>

Grace ==
  /\ phase = "ASSIGNING"
  /\ phase' = "SUBMISSION_GRACE"
  /\ UNCHANGED <<boundaryFixed, assignmentIssued, acceptedShares,
                  maskOpened, maskMatchesCommitment, acceptedWinner, winnerDetectable>>

Finalize ==
  /\ phase = "SUBMISSION_GRACE"
  /\ phase' = "RECEIPT_FINALIZING"
  /\ UNCHANGED <<boundaryFixed, assignmentIssued, acceptedShares,
                  maskOpened, maskMatchesCommitment, acceptedWinner, winnerDetectable>>

FixBoundary ==
  /\ phase = "RECEIPT_FINALIZING"
  /\ phase' = "OPENING"
  /\ boundaryFixed' = TRUE
  /\ UNCHANGED <<assignmentIssued, acceptedShares, maskOpened,
                  maskMatchesCommitment, acceptedWinner, winnerDetectable>>

Open ==
  /\ phase \in {"OPENING", "TIMED_RECOVERY"}
  /\ boundaryFixed
  /\ phase' = "OPENED"
  /\ maskOpened' = TRUE
  /\ winnerDetectable' = acceptedWinner
  /\ UNCHANGED <<boundaryFixed, assignmentIssued, acceptedShares,
                  maskMatchesCommitment, acceptedWinner>>

Abort ==
  /\ phase \in {"SELECTING_COMMITTEE", "MPC_SETUP", "MASK_COMMITTED",
                  "ASSIGNING", "SUBMISSION_GRACE", "RECEIPT_FINALIZING", "OPENING"}
  /\ phase' = "ABORTED"
  /\ UNCHANGED <<boundaryFixed, assignmentIssued, acceptedShares,
                  maskOpened, maskMatchesCommitment, acceptedWinner, winnerDetectable>>

Recover ==
  /\ phase = "ABORTED"
  /\ acceptedShares
  /\ phase' = "TIMED_RECOVERY"
  /\ boundaryFixed' = TRUE
  /\ UNCHANGED <<assignmentIssued, acceptedShares, maskOpened,
                  maskMatchesCommitment, acceptedWinner, winnerDetectable>>

CloseEmptyAbort ==
  /\ phase = "ABORTED"
  /\ ~acceptedShares
  /\ phase' = "CLOSED"
  /\ UNCHANGED <<boundaryFixed, assignmentIssued, acceptedShares,
                  maskOpened, maskMatchesCommitment, acceptedWinner, winnerDetectable>>

Close ==
  /\ phase = "OPENED"
  /\ phase' = "CLOSED"
  /\ UNCHANGED <<boundaryFixed, assignmentIssued, acceptedShares,
                  maskOpened, maskMatchesCommitment, acceptedWinner, winnerDetectable>>

Next == Setup \/ Commit \/ Assign \/ AcceptWinner \/ Grace \/ Finalize \/
        FixBoundary \/ Open \/ Abort \/ Recover \/ CloseEmptyAbort \/ Close

TypeOK ==
  /\ phase \in {"SELECTING_COMMITTEE", "MPC_SETUP", "MASK_COMMITTED", "ASSIGNING",
                  "SUBMISSION_GRACE", "RECEIPT_FINALIZING", "OPENING", "OPENED",
                  "CLOSED", "ABORTED", "TIMED_RECOVERY"}
  /\ boundaryFixed \in BOOLEAN
  /\ assignmentIssued \in BOOLEAN
  /\ acceptedShares \in BOOLEAN
  /\ maskOpened \in BOOLEAN
  /\ maskMatchesCommitment \in BOOLEAN
  /\ acceptedWinner \in BOOLEAN
  /\ winnerDetectable \in BOOLEAN

NoAssignmentBeforeCommit == assignmentIssued => phase \notin {"SELECTING_COMMITTEE", "MPC_SETUP"}
NoOpenBeforeBoundary == maskOpened => boundaryFixed
OpenedMaskMatches == maskOpened => maskMatchesCommitment
WinnerRecovery == (phase \in {"OPENED", "CLOSED"} /\ acceptedWinner) => winnerDetectable
AbortedAcceptedMustRecover == (phase = "CLOSED" /\ acceptedShares) => maskOpened

Spec == Init /\ [][Next]_vars

====
