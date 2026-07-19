# Committee-risk model

`meshmine-committee-risk` evaluates each role independently, then reports a
conservative deployment union bound. Per-selection binomial and finite-population
hypergeometric tails are exact rational values. Per-role annualization is a
stable floating-point presentation of `1 - (1-p)^events`; it is display evidence
only. Release authorization instead compares the exact rational Bonferroni bound
`min(1, events * p)` with the exact binary-rational value represented by the
configured finite `f64` target. Floating-point rounding therefore cannot turn a
failing deployment bound into a passing release report. Work and payout
arithmetic do not use floating point either.

Correlation groups are disjoint fractions of eligible selection weight. Each
group has mutually exclusive normal, whole-group outage, and whole-group
compromise states. The evaluator enumerates all states exactly, with a maximum
of eight groups. Liveness uses a categorical committee model, so adversarial
refusal and too-few-honest-online events are combined without double counting.

`eligible_adversarial_fraction` is deliberately separate from observed
`adversarial_work_fraction`. The former must be measured over the finalized
eligibility lookback; their ratio exposes lookback-induced concentration rather
than assuming it away.

Role overlap is modeled as a fixed number of shared committee seats and reports
the exact joint certificate-capture probability against the independent-role
product. Parallel lanes can use independently selected committees or one shared
committee. The deployment bound remains conservative because arbitrary
multi-role overlaps are not reduced through incomplete pairwise
inclusion-exclusion.

Example commands:

```text
cargo run --locked -p meshmine-committee-risk -- evaluate \
  --config specs/risk-profile.example.json --monte-carlo 100000

cargo run --locked -p meshmine-committee-risk -- evaluate \
  --config specs/risk-profile.example.json --enforce
```

The second command exits unsuccessfully when either configured annual bound is
exceeded. The example is illustrative and is expected to require tuning; it is
not a mainnet profile.

Every successful report also exposes a
`risk_profile_commitment`: a domain-separated BLAKE2b-256 commitment to every
probability, correlation group, rotation/lookback/lane choice, annual target,
role name and threshold, eligible population, and overlap input. Role names
must be unique. Report internals are not publicly mutable outside the risk
crate, so the committee release API can bind a locally computed passing report
to the exact canonical role, roster size, certificate threshold, and opening
threshold rather than trusting caller-created booleans. The commitment records
which reviewed assumptions authorized a local release; it does not prove that
those assumptions accurately describe a real deployment.
