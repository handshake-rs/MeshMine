# Executable protocol models

These finite TLA+ models cover the MM-0001 section 24.4 safety state:

- `mask_session`: no assignment before commitment, no opening before the receipt boundary, and timed recovery for accepted winners;
- `receipt_close`: set-based work-key credit, append-only batches, and a single final close root;
- `payout_snapshot`: closure before entropy, deterministic single-plan state, canonical payment, and reorg rollback.

Run each model with TLC and its adjacent configuration, for example:

```sh
java -cp /path/to/tla2tools.jar tlc2.TLC -config models/mask-session.cfg models/mask_session.tla
```

The Rust lifecycle guards in `meshmine-types::state` enforce the same legal
transitions at runtime. Run exhaustive breadth-first checking with the
TLC tool on the exact candidate model and require every invariant to hold.
Model checking is an evaluation gate and does not replace independent protocol
or implementation review.
