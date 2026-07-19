# Static research role assumptions

This is the explicit Phase-0/local profile required by MM-0001 §3.4. It is an
illustrative input to `meshmine-committee-risk`, not a mainnet recommendation.
The example currently fails its configured annual bounds, so dynamic/mainnet
authorization remains disabled.

| Role | `n` | `t_sign` | `t_open` | Max corrupt before secrecy/certificate failure | Max unavailable while live | Synchrony | Selection lookback | Rotation | Annual capture target | Annual liveness target |
|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|
| Mask | 32 | 23 | 21 | 20 for mask secrecy; 22 for certificate safety | 9 for signing; 11 for opening | Published bounded-delay research clock | 2,016 HNS blocks (minimum 1,008) | 86,400 s | ≤1e-6 | ≤1e-3 |
| Receipt | 32 | 23 | N/A (`23` risk-tool action threshold) | 22 for certificate safety; no secret state | 9 | Published bounded-delay research clock | 2,016 HNS blocks (minimum 1,008) | 86,400 s | ≤1e-6 | ≤1e-3 |
| Availability | 32 | 23 | N/A (`23` risk-tool action threshold) | 22 for certificate safety; no secret state | 9 | Published bounded-delay research clock | 2,016 HNS blocks (minimum 1,008) | 86,400 s | ≤1e-6 | ≤1e-3 |
| Settlement | 32 | 23 | N/A (`23` risk-tool action threshold) | 22 for certificate safety; no secret state | 9 | Published bounded-delay research clock | 2,016 HNS blocks (minimum 1,008) | 86,400 s | ≤1e-6 | ≤1e-3 |

The synchrony assumption is concretized in `regtest-profile.md`: at most 2,000
ms accepted wall-clock skew, a 10,000 ms assignment window, 3,000 ms submission
grace, 5,000 ms receipt finalization, and timed opening 1,000–10,000 ms after a
fixed receipt boundary. Excess skew pauses new assignments and never extends a
certified boundary.

Correlated hosting/jurisdiction events, work concentration, role overlap, and
parallel lanes are supplied separately in `risk-profile.example.json`. Actual
deployment values must be measured and must pass `--enforce`; copying this
table does not satisfy a release gate.
