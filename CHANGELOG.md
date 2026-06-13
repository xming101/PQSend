# Changelog

All notable changes to PQSend are documented in this file.

PQSend follows semantic versioning for release labels, but all package formats
and behavior remain experimental and may change without backward compatibility
before `v1.0.0`.

## [Unreleased]

## [v0.1.0-alpha.1] - 2026-06-13

First experimental encrypted package alpha. This release is unaudited,
X25519-only, not post-quantum-secure, and not ready for sensitive real-world
data.

### Added

- age-backed binary age v1 adapter for one X25519 recipient
- fixed 20-byte `.pqsend` public envelope
- one-file `.pqsend` package creation and authenticated opening
- encrypted internal single-file manifest that hides the original filename
  from public package metadata
- explicit key-file `keygen`, `pack`, `open`, and `inspect` CLI workflow
- local human-readable security receipts
- security-sensitive tests covering tampering, truncation, wrong identities,
  filename leakage, inspect leakage, unsafe filenames, and overwrite refusal

### Security and privacy notes

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
- contact integration with package operations
- folder support
- multiple recipients
- sender signatures
- password mode
- GUI
- relay server
- chat
- a stable package format
- an external security audit

See [the full release notes](docs/releases/v0.1.0-alpha.1.md).

[Unreleased]: https://github.com/xming101/PQSend/compare/v0.1.0-alpha.1...HEAD
[v0.1.0-alpha.1]: https://github.com/xming101/PQSend/releases/tag/v0.1.0-alpha.1
