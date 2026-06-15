# Changelog

All notable changes to PQSend are documented in this file.

PQSend follows semantic versioning for release labels, but all package formats
and behavior remain experimental and may change without backward compatibility
before `v1.0.0`.

## [Unreleased]

## [v0.1.0-alpha.1] - 2026-06-13

First experimental encrypted package alpha for PQSend. PQSend is an
experimental `.pqsend` encrypted package format with a Rust reference CLI for
private file delivery.

This release is experimental, unaudited, X25519-only, not
post-quantum-secure, built around an unstable package format, and not ready for
sensitive real-world data.

### Added

- canonical `.pqsend` package-format, security-model, threat-model, receipt,
  contact, and compatibility documentation
- age-backed binary age v1 adapter for exactly one X25519 recipient
- fixed 20-byte `.pqsend` public envelope
- one-file `.pqsend` package creation and authenticated opening
- encrypted internal single-file manifest that hides the original filename
  from public package metadata
- explicit recipient-file and identity-file `keygen`, `pack`, and `open`
  workflow
- local contact workflow with recipient-bound fingerprint verification and
  explicit one-operation unverified-contact override
- safe public `inspect` command that reads only the fixed public envelope
- local human-readable security receipts
- initial experimental valid and invalid `v0-alpha` test vectors
- security-sensitive tests covering tampering, truncation, wrong identities,
  filename and contact-metadata leakage, inspect leakage, unsafe filenames,
  contact trust-state transitions, strict vector behavior, and overwrite
  refusal

### Security and privacy notes

- PQSend delegates recipient encryption and authenticated payload protection to
  the Rust `age` crate and does not implement custom cryptographic primitives.
- The v0.1 file-size limit is 64 MiB (`67,108,864` bytes).
- The original filename is encrypted inside the package, but the outer package
  filename is not. Users who want to avoid filename leakage must not name the
  outer `.pqsend` package after the original file.
- Package creation, key generation, and extraction refuse to overwrite
  existing files.
- Opening rejects unsafe authenticated filenames and validates the complete
  package before publishing plaintext output.

### Not included

- post-quantum support
- folders or multiple files
- multiple recipients
- sender signatures
- password mode
- GUI
- networking, relay/server behavior, or cloud sync
- messaging or chat
- custom cryptography
- a stable package format
- an external security audit

See [the full release notes](docs/RELEASES/v0.1.0-alpha.1.md).

Release documentation:

- [Package format](docs/FORMAT.md)
- [Security model](docs/SECURITY-MODEL.md)
- [Threat model](docs/THREAT-MODEL.md)
- [Contacts](docs/CONTACTS.md)
- [Security receipts](docs/RECEIPTS.md)
- [Compatibility](docs/COMPATIBILITY.md)
- [Initial test vectors](test-vectors/README.md)

[Unreleased]: https://github.com/xming101/PQSend/compare/v0.1.0-alpha.1...HEAD
[v0.1.0-alpha.1]: https://github.com/xming101/PQSend/releases/tag/v0.1.0-alpha.1
