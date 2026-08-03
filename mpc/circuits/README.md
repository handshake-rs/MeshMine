# Mask-hash MPC circuit

`generate_mask_hash_circuit` emits a deterministic Bristol-Fashion Boolean
circuit with two 256-wire inputs (`parent`, then secret `mask`) and one
256-wire output:

```text
BLAKE2b-256(parent || mask)
```

Bits are least-significant first within each byte; bytes remain in HNS wire
order. The circuit uses only `XOR`, `AND`, and `INV` gates and can therefore be
loaded by binary MPC runtimes such as MP-SPDZ's `Compiler.circuit.Circuit`.
Generate it without checking a multi-megabyte derived file into the repository:

```sh
cargo run --locked --quiet -p meshmine-mpc-api --bin generate_mask_hash_circuit \
  --out Programs/Circuits/meshmine_mask_hash.txt
```

The exporter refuses to replace an existing circuit file. The current frozen
shape is 209,858 gates and 210,370 wires; the tests enforce a 250,000-gate
resource ceiling.

The Rust test evaluates 64 cases per machine word and compares 10,000
deterministic parent/mask pairs with `meshmine-hns`'s HNS BLAKE2b oracle. This
proves the clear semantics and deterministic circuit shape; it does not prove
the security of an MPC runtime by itself. The separate distributed adapter in
[`../mp-spdz/README.md`](../mp-spdz/README.md) binds this circuit to an executed
evaluation setup and durable per-member shares; neither that composition nor the
trusted-coordinator simulation backend is production-eligible.
