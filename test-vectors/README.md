# `.pqsend` Test Vectors

This directory is the publication home for `.pqsend` package compatibility and
parser test vectors. The package bytes and required parsing behavior are
defined by the canonical [format specification](../docs/FORMAT.md).

PQSend is experimental, unaudited, X25519-only, not post-quantum-secure, and
unstable before `v1.0.0`. These experimental vectors define the current
reference behavior and compatibility expectations for the named alpha format.
They may change incompatibly before `v1.0.0` and do not imply pre-v1 format
stability.

## Layout

- [`v0-alpha/`](v0-alpha/README.md) contains the current experimental vector
  set and its machine-readable metadata.
- [`v0-alpha/valid/`](v0-alpha/valid/README.md) contains vectors that
  implementations of the named experimental format are expected to accept.
- [`v0-alpha/invalid/`](v0-alpha/invalid/README.md) contains vectors that
  implementations are expected to reject.

Each published vector set must document:

- the exact package-format version, mode, and backend identifier
- expected acceptance or rejection outcome
- generation or mutation procedure
- expected public envelope values for valid vectors
- the rejection reason category for invalid vectors
- whether private test identities and expected plaintext are intentionally
  included for interoperability testing
- hashes of the exact vector files

Test vectors must never contain sensitive real-world plaintext, personal data,
or real private keys. Any included test identity is deliberately public
fixture material only. Never use a test identity or recipient from this
directory for real secrets.

Valid encrypted package vectors are fixed snapshots, but newly generated
ciphertext may differ because encryption uses randomness. Implementations
should compare the documented restored result and validation behavior rather
than expecting fresh encryption to reproduce snapshot bytes. Deterministic
vectors are preferred wherever encryption randomness is not involved.

The Rust reference implementation loads and verifies this corpus from
`crates/pqsend-core/tests/test_vectors.rs`. See
[`docs/COMPATIBILITY.md`](../docs/COMPATIBILITY.md) for the current
compatibility policy.
