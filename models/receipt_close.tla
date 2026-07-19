---- MODULE receipt_close ----
EXTENDS Naturals, FiniteSets, TLC

WorkKeys == {"w1", "w2", "w3"}
Roots == {"r1", "r2", "r3"}

VARIABLES credited, batchSequence, lastBatchRoot, closed, closeRoot
vars == <<credited, batchSequence, lastBatchRoot, closed, closeRoot>>

Init ==
  /\ credited = {}
  /\ batchSequence = 0
  /\ lastBatchRoot = "none"
  /\ closed = FALSE
  /\ closeRoot = "none"

Credit(workKey, root) ==
  /\ ~closed
  /\ workKey \in WorkKeys \ credited
  /\ root \in Roots
  /\ credited' = credited \cup {workKey}
  /\ batchSequence' = batchSequence + 1
  /\ lastBatchRoot' = root
  /\ UNCHANGED <<closed, closeRoot>>

Close ==
  /\ ~closed
  /\ batchSequence > 0
  /\ closed' = TRUE
  /\ closeRoot' = lastBatchRoot
  /\ UNCHANGED <<credited, batchSequence, lastBatchRoot>>

Next == (\E workKey \in WorkKeys, root \in Roots: Credit(workKey, root)) \/ Close

TypeOK ==
  /\ credited \subseteq WorkKeys
  /\ batchSequence \in 0..Cardinality(WorkKeys)
  /\ lastBatchRoot \in Roots \cup {"none"}
  /\ closed \in BOOLEAN
  /\ closeRoot \in Roots \cup {"none"}

OneCreditPerWorkKey == Cardinality(credited) = batchSequence
CloseUsesFinalBatch == closed => closeRoot = lastBatchRoot
ClosedIsImmutable == closed => closeRoot # "none"

Spec == Init /\ [][Next]_vars

====
