# PQSend Specification Pointer

This file is retained for compatibility with existing links, contributor
workflows, and tools that expect a top-level `SPEC.md`.

The canonical implementer-facing specification for `.pqsend` package bytes is
[docs/FORMAT.md](docs/FORMAT.md). Do not maintain a second wire-format
specification here.

PQSend is an experimental encrypted package format and Rust reference CLI for
private file delivery. The current format contains exactly one file encrypted
for exactly one age X25519 recipient. It is X25519-only, not
post-quantum-secure, unaudited, and unstable before `v1.0.0`.

Use these documents with the format specification:

- [Security model](docs/SECURITY-MODEL.md)
- [Threat model](docs/THREAT-MODEL.md)
- [Contacts model](docs/CONTACTS.md)
- [Receipts model](docs/RECEIPTS.md)
- [Compatibility rules](docs/COMPATIBILITY.md)
- [Design decisions](docs/design-decisions.md)
- [Test vectors](test-vectors/README.md)

Package or security-boundary changes must update the canonical documents,
relevant design decisions, and security-sensitive tests. Keep this pointer
accurate when document locations or the high-level current scope change.
