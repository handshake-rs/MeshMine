# Executable protocol models

These finite TLA+ models cover the MM-0001 section 24.4 safety state:

- `mask_session`: no assignment before commitment, no opening before the receipt boundary, and timed recovery for accepted winners;
- `receipt_close`: set-based work-key credit, append-only batches, and a single final close root;
- `payout_snapshot`: closure before entropy, deterministic single-plan state, canonical payment, and reorg rollback.

Run each model with TLC and its adjacent configuration, for example:

```sh
java -cp /path/to/tla2tools.jar tlc2.TLC -config models/mask-session.cfg models/mask_session.tla
```

The Rust lifecycle guards in `meshmine-types::state` enforce the same legal transitions at runtime. With TLC 1.8.0, exhaustive breadth-first checking found no invariant violation across 24 reachable mask states, 43 receipt states, and 17 payout states. Model checking is a research validation artifact, not a production security audit.
