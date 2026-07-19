# Stage 1 isolated regtest profile

Handshake regtest uses compact target `0x207fffff`, whose decoded target has only one guaranteed leading-zero bit. MM-0001's production blind band requires `p > d > 0`, which is impossible at that regtest difficulty.

WP3 therefore uses a test-only capture profile:

- `q = 1`
- `d = 0`
- `T_capture = 2^255 - 1`
- the locally generated mask has its most-significant bit cleared

This preserves the winner-implies-capture invariant needed by the end-to-end test, but it does not exercise a nonzero blind band and must never be enabled on testnet or mainnet. Nonzero blind-band behavior is covered by later simulation profiles with harder targets.

The isolated miner process receives only the 256-byte miner header and capture target. The regtest driver retains and opens the mask after capture, reconstructs the ordinary HNS block, and asks an unmodified in-memory `hsd` node to accept it.

`meshmine-node research-mine-once --stock-regtest-compat` implements this exact
`0x207fffff`, `q=1,d=0` profile against the `getwork`, `getblockhash`, and
`submitwork` RPCs of an unmodified isolated hsd regtest node. The flag is the
only route by which the research VSS backend accepts `d=0`; without it, the
one-shot command requires a nonzero blind band and a correspondingly harder
synthetic target. It verifies the regtest network and exact hsd regtest genesis
before binding the CLI and immediately before submission, then preserves the
work-to-acceptance sequence as immutable schema-v3 state. Full operational and
replay boundaries are in
[`RESEARCH-MINE-ONCE.md`](../bins/meshmine-node/RESEARCH-MINE-ONCE.md).

## Published research clock profile

The local/static-committee research profile uses monotonic elapsed timers with these maximum wall/schedule bounds:

| Parameter | Bound |
|---|---:|
| Accepted peer wall-clock skew | 2,000 ms |
| Assignment window | 10,000 ms |
| Submission grace | 3,000 ms |
| Receipt finalization | 5,000 ms |
| Timed opening after fixed receipt boundary | 1,000–10,000 ms |

Detected excess skew pauses new assignments and rejects the inconsistent session schedule; it never extends an already certified accepted-share boundary. Production/testnet deployments must publish their own measured profile.
