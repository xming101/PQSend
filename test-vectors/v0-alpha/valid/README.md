# Valid v0-alpha Vectors

> [!WARNING]
> PQSend is experimental and unaudited. The current backend is X25519-only and
> not post-quantum-secure. The pre-`v1.0.0` format is unstable.

These vectors are expected to be accepted by implementations supporting the
named experimental v0-alpha behavior:

- one deterministic canonical public envelope
- one deterministic canonical inner single-file plaintext structure
- small, empty-file, and filename-hiding encrypted package snapshots

Expected restored filenames, plaintext SHA-256 values, exact vector hashes,
and key-fixture availability are recorded in
[`../manifest.toml`](../manifest.toml).

The `.pqsend` ciphertext snapshots depend on encryption randomness. Fresh
encryption is expected to restore the same semantics, not reproduce the same
ciphertext bytes.
