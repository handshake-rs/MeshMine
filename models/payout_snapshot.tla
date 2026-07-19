---- MODULE payout_snapshot ----
EXTENDS Naturals, TLC

Roots == {"s1", "s2"}
Plans == {"p1", "p2"}

VARIABLES phase, snapshotSequence, snapshotRoot, entropyKnown,
          plan, paidSequence, canonical
vars == <<phase, snapshotSequence, snapshotRoot, entropyKnown,
          plan, paidSequence, canonical>>

Init ==
  /\ phase = "ACCUMULATING_WORK"
  /\ snapshotSequence = 1
  /\ snapshotRoot = "none"
  /\ entropyKnown = FALSE
  /\ plan = "none"
  /\ paidSequence = 0
  /\ canonical = FALSE

CloseSnapshot(root) ==
  /\ phase = "ACCUMULATING_WORK"
  /\ root \in Roots
  /\ ~entropyKnown
  /\ phase' = "SNAPSHOT_CLOSED"
  /\ snapshotRoot' = root
  /\ UNCHANGED <<snapshotSequence, entropyKnown, plan, paidSequence, canonical>>

RevealEntropy ==
  /\ phase = "SNAPSHOT_CLOSED"
  /\ phase' = "WAITING_FOR_ENTROPY"
  /\ entropyKnown' = TRUE
  /\ UNCHANGED <<snapshotSequence, snapshotRoot, plan, paidSequence, canonical>>

BuildPlan(p) ==
  /\ phase = "WAITING_FOR_ENTROPY"
  /\ entropyKnown
  /\ p \in Plans
  /\ phase' = "PAYABLE"
  /\ plan' = p
  /\ UNCHANGED <<snapshotSequence, snapshotRoot, entropyKnown, paidSequence, canonical>>

Pay ==
  /\ phase = "PAYABLE"
  /\ paidSequence = 0
  /\ phase' = "INCLUDED_IN_HNS_BLOCK"
  /\ paidSequence' = snapshotSequence
  /\ UNCHANGED <<snapshotSequence, snapshotRoot, entropyKnown, plan, canonical>>

Confirm ==
  /\ phase = "INCLUDED_IN_HNS_BLOCK"
  /\ phase' = "CANONICAL"
  /\ canonical' = TRUE
  /\ UNCHANGED <<snapshotSequence, snapshotRoot, entropyKnown, plan, paidSequence>>

Reorg ==
  /\ phase \in {"INCLUDED_IN_HNS_BLOCK", "CANONICAL"}
  /\ phase' = "PAYABLE"
  /\ paidSequence' = 0
  /\ canonical' = FALSE
  /\ UNCHANGED <<snapshotSequence, snapshotRoot, entropyKnown, plan>>

Next == (\E root \in Roots: CloseSnapshot(root)) \/ RevealEntropy \/
        (\E p \in Plans: BuildPlan(p)) \/ Pay \/ Confirm \/ Reorg

TypeOK ==
  /\ phase \in {"ACCUMULATING_WORK", "SNAPSHOT_CLOSED", "WAITING_FOR_ENTROPY",
                  "PAYABLE", "INCLUDED_IN_HNS_BLOCK", "CANONICAL"}
  /\ snapshotSequence = 1
  /\ snapshotRoot \in Roots \cup {"none"}
  /\ entropyKnown \in BOOLEAN
  /\ plan \in Plans \cup {"none"}
  /\ paidSequence \in {0, 1}
  /\ canonical \in BOOLEAN

SnapshotBeforeEntropy == entropyKnown => snapshotRoot # "none"
OneSnapshotRoot == snapshotRoot = "none" \/ snapshotRoot \in Roots
PlanAfterEntropy == plan # "none" => entropyKnown
CanonicalPaid == canonical => paidSequence = snapshotSequence

Spec == Init /\ [][Next]_vars

====
