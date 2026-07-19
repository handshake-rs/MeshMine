# WP13 research committee selection profile

Dynamic selection is implemented as a research profile, not a frozen mainnet
algorithm. Eligibility leaves are sorted by operator public key and commit to
finalized work plus a role mask. The snapshot root must be finalized at least
the configured lookback before the selection anchor. Entropy must begin after
snapshot finalization and end no later than that anchor.

Each role seed commits to the snapshot ID/root, delayed HNS entropy window,
prior beacon, ASCII role tag, and epoch under
`meshmine/committee-seed/v2`. Members are drawn sequentially without
replacement. Each 512-bit BLAKE2b candidate is rejection-sampled against the
remaining exact work total; the winner is removed before the next draw. Draw
order, retry counters, and the final sorted roster are transcript-committed.

The bootstrap transition is explicit:

- Phase 0 uses only the published static roster and has no eligibility root.
- Phase 1 keeps an explicit number of canonical static seats and fills the rest
  through finalized-work selection.
- Phase 2 uses finalized-work selection; static members are observers only.

Phase 0 artifacts carry a visible static-trust notice. Dynamic artifacts remain
`production_eligible=false` until both WP12 annual bounds pass and an explicit
review release is supplied. Deterministic verification always clears a remote
candidate's production flag and risk commitment; it cannot import another
operator's release assertion. The separate local authorization step accepts
only a non-production dynamic roster whose canonical role, member count,
certificate threshold, and opening threshold exactly match a uniquely named
role in the immutable passing risk report, then records that report's full
profile commitment. The exact sortition, Phase 1 composition, eligibility-root
authority, and accuracy of the reviewed deployment assumptions remain
protocol-freeze or operational questions in `OPEN-QUESTIONS.md`.

Roster verification recomputes the snapshot, seed, draw transcript, members,
role, epoch, and thresholds. Certificate verification then checks every signer
against that exact role/epoch roster. The shared certificate boundary rejects
empty rosters, rosters above 256 members, and thresholds outside
`1..=member_count`, including for callers that construct a roster directly.
Replacement after liveness failure accepts only a verified next-epoch roster
with enough members outside the recorded unavailable set; no outgoing-committee
signature is treated as permission to rotate.
