# `.pqsend` Test Vectors

This directory is the publication home for `.pqsend` package compatibility and
parser test vectors.

PQSend is experimental, unaudited, X25519-only, not post-quantum-secure, and
unstable before `v1.0.0`. No normative cross-implementation vector set has
been published yet.

## Layout

- [`v0-alpha/valid/`](v0-alpha/valid/README.md) is reserved for packages that
  implementations of the named experimental format must accept.
- [`v0-alpha/invalid/`](v0-alpha/invalid/README.md) is reserved for packages
  that implementations must reject.

Each published vector set must document:

- the exact package-format version, mode, and backend identifier
- expected acceptance or rejection outcome
- generation or mutation procedure
- expected public envelope values for valid vectors
- the rejection reason category for invalid vectors
- whether private test identities and expected plaintext are intentionally
  included for interoperability testing
- hashes of the exact vector files

Test vectors must never contain sensitive real-world plaintext or keys.
Pre-v1 vectors may be replaced or versioned incompatibly, but their applicable
format and expected outcome must remain explicit.

The current Rust security-sensitive tests live under `crates/pqsend-core/tests`
and `crates/pqsend-cli/tests`. They are not a substitute for published
cross-implementation vectors.
