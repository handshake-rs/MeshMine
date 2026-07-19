# MP-SPDZ distributed setup conformance

The generated mask-hash circuit and distributed setup were compiled and run
against upstream MP-SPDZ commit
`6a2256e327b507918859f605735543bb32a39d9d`. The reviewed runtime pairs
malicious dishonest-majority MASCOT arithmetic with Tinier binary sharing and
uses classic daBits for domain conversion.

`meshmine_distributed_setup.mpc` is the next-stage mixed-circuit setup
program. For compile-time profile parameters `Q`, `D`, `MEMBERS`, and
`THRESHOLD`, it:

- reads the canonical parent as 256 common public bits, LSB-first within each
  byte;
- maps MM-0001's MSB-first leading-mask positions to those circuit wires;
- jointly samples the mask and repeats inside MPC until the blind band is
  nonzero, without biased zero-to-one remapping;
- computes `maskHash` through the generated Boolean circuit;
- generates degree-`THRESHOLD - 1` GF(256) polynomials whose constants are the
  32 secret mask bytes; and
- uses arithmetic private output to give each computing party only its own
  32-byte opening share.

Every party receives exactly 103 native little-endian signed 64-bit records
(824 bytes):

```text
magic, version, q, d, members, threshold,
parent[32], maskHash[32], blindBandValid, localShare[32]
```

The Rust adapter requires exact length, nonnegative byte records, magic
`0x4d4d4453`, version `1`, validity `1`, and exact request/profile/parent
agreement. Public records must agree across signed member contributions. Only
the final 32 records are private and they remain local to that member.

The mixed binary-to-arithmetic conversion requires MP-SPDZ's classic daBit
mode. A three-member, threshold-two parser/resource fixture compiles with:

```sh
./compile.py -M -X meshmine_distributed_setup 16 8 3 2
```

`-M` preserves memory-instruction order because the binary output layout is a
security boundary. The rejection loop makes static preprocessing bounds
infinite, as expected for unbounded uniform rejection sampling. The corrected
three-party run on the local ARM64 host completed in 14.9949 seconds, sent
1,153.61 MB globally,
produced three distinct 824-byte outputs, reconstructed from parties 0 and 1,
and matched the public HNS hash exactly:

```text
maskHash = 107e32cd77fadeebebdc0f485cc4c57f00e16444ec71d9a71ac272dbd9609db7
mask     = 00001d0d6d6d345235fb359683879d0a8fbfe697a5c8d3ea8afad03ccc07fd28
```

The first 16 mask bits are zero and the following eight-bit blind band is
nonzero.

Run the malicious fixture with a 256-bit public input (the zero-parent file is
provided only for conformance):

```sh
cp /path/to/MeshMine/mpc/mp-spdz/meshmine_distributed_setup.mpc Programs/Source/
cp /path/to/MeshMine/mpc/mp-spdz/zero-parent.public-input \
  Programs/Public-Input/meshmine_distributed_setup-16-8-3-2
./compile.py -M -X meshmine_distributed_setup 16 8 3 2
Scripts/mascot.sh meshmine_distributed_setup-16-8-3-2 -N 3 -OF .
```

Then verify the frozen artifacts, all output framing, identity-bound member
imports, public commitment assembly, and threshold reconstruction:

```sh
cargo run --locked --quiet -p meshmine-mpc-api --bin verify_mp_spdz_fixture -- \
  /path/to/MP-SPDZ
```

The reviewed artifact ID is
`0524ed532663f4ef9342a20f9e9ac9eaf28dedf44785e7fdfe0629c5fc311906`.
Its BLAKE2b-256 identities are:

| Artifact | Bytes | Digest |
|---|---:|---|
| setup source | 4,344 | `f40986abfa8865789377feb025ca4c34659c1045021991baead780ec7f7a8b6d` |
| Bristol mask-hash circuit | 5,683,435 | `efcbf93386e192a1147f314375620701f919a25b1b9bb510ee2c78d44847c467` |
| `16/8/3/2` bytecode | 5,454,016 | `af2e3892d9c950ebf24cf5af0fe3d054f65667d34c646e6dab613318b8634479` |
| `-M` schedule | 161 | `9783dbea21ef5215e346fd07a8d9dce164a4998f0aee124f52fd4b7be9f60034` |
| `mascot-party.x` | 42,939,888 | `1d501ce594aae0adf9a2e55c5dda8418d44c05b174f8612780220f81d9b76626` |
| `libSPDZ.so` | 14,986,712 | `e77c4de51cb35ebd998f39dd84d5a773cbaba813a717da5f544523bdf189da2b` |

The executable/library hashes are build-specific ARM64 conformance identities,
not portable release binaries.

## Security model and trust boundary

The local research claim assumes MP-SPDZ's malicious
dishonest-majority MASCOT/Tinier security: setup privacy and correctness-or-
abort require at least one honest computing party, computational assumptions,
uncompromised local processes/keys, and authenticated reliable channels. The
current repository does not provide those multi-host channels or attest the
remote executable. Artifact hashes prove what a local member approved, and
member signatures bind what it claims to have received; neither proves a
remote host ran that artifact.

MPC corruption and later Shamir opening are separate thresholds. Fewer than
`THRESHOLD` valid opening shares reveal no mask through the Shamir layer; any
`THRESHOLD` colluding or timely opening members can reconstruct it. A malicious
MPC participant can abort or later refuse its opening share. The adapter makes
no fairness, guaranteed-output-delivery, or identifiable-abort claim. Liveness
therefore requires enough honest online members and a deployment-specific
message-delay assumption through setup and timed opening.

The signed hash commitments verify that a revealed share is the one each
member durably committed. They are not a standalone publicly verifiable
polynomial commitment; consistency relies on the allowlisted MPC
correctness-or-abort execution plus an honest opening threshold. These are the
reasons the adapter reports `production_eligible=false` despite setting its
protocol-level `malicious_secure` property.

From an MP-SPDZ checkout at that revision, copy
`meshmine_mask_hash_check.mpc` into `Programs/Source`, then generate the circuit
from the MeshMine workspace:

```sh
cargo run --locked --quiet -p meshmine-mpc-api --bin generate_mask_hash_circuit -- \
  --out /path/to/MP-SPDZ/Programs/Circuits/meshmine_mask_hash.txt
```

Compile the conformance fixture:

```sh
./compile.py -B 64 meshmine_mask_hash_check
```

The simple circuit-only checked compile consumed the complete 209,858-gate file
and reported 73,728 binary triples and 3,243 virtual-machine rounds. That
fixture is not a MeshMine setup protocol: its zero parent and single private
mask input exist only to exercise the external parser/compiler.

The end-to-end verifier above also reads all three private outputs centrally,
so it is test-only. A real member calls the local import API with one file;
the assembler sees signed hashes, never shares. Even that separation does not
make the implementation production-audited or provide output delivery under
party refusal.
