# MeshMine Core v2 research wire profile

Status: frozen for the Stage 0 reference implementation and cross-language vectors. This profile is not a mainnet security claim.

MM-0001 fixes field order and integer endianness but leaves several low-level representations implicit. The reference implementation resolves them as follows:

- Lengths and vector counts use minimal unsigned LEB128. A decoder rejects redundant terminal zero groups, overflow, and values above the field's explicit bound.
- `U256` target/chainwork values and `U512` work values are fixed-width unsigned big-endian byte strings. Ordinary `u8`, `u16`, `u32`, and `u64` values remain little-endian.
- `Option<T>` is encoded as one byte: `0x00` for absent or `0x01` followed by `T`. Other tags are invalid.
- Domain tags are encoded as a minimal-varint length followed by ASCII bytes before the canonical unsigned object body.
- A direct Ed25519 signature is exactly 64 bytes. Its suite is obtained from the operator record (`1` means Ed25519).
- A certificate `SignatureSet` begins with a little-endian `u16` suite and a length-prefixed vector of `(32-byte signer public key, 64-byte signature)` entries. Entries must be strictly sorted by public key, with no duplicates. Suite `1` is Ed25519.
- `BodyErasureDescriptorV2` and `BodyAvailabilityCertificateV2` begin with `protocol_version` and `network_id`, following the global MM-0001 encoding rule even though those two fields are omitted from their abbreviated object diagrams.
- `PayoutSnapshotV2` and `PayoutPlanV2` carry a trailing `SignatureSet`, because MM-0001 requires settlement certification and states that their IDs exclude signatures despite omitting those fields from the abbreviated diagrams.
- An object ID is BLAKE2b-256 over `varint(tag_length) || tag || canonical_unsigned_body`. Signature material and the ID itself are never part of that preimage.

These decisions must be independently reviewed before any production wire freeze. Changes require a protocol-version bump or an explicit compatibility rule.

