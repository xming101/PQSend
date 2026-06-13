# Design Decisions

This log records decisions that shape multiple parts of PQSend. It is not a
substitute for `SPEC.md` or `THREAT_MODEL.md`.

## DD-001: Local-first portable packages

PQSend creates portable `.pqsend` files that can be transported by unrelated
tools. Encryption and decryption happen locally. PQSend has no telemetry and
does not require or currently provide a network service.

## DD-002: A package layer, not stronger cryptography

PQSend distinguishes itself from `age` through an opinionated, human-oriented
package and safety layer, not by claiming stronger cryptography. The package
layer provides encrypted internal metadata, contacts and verification status,
security receipts, and safe defaults.

## DD-003: Established encryption backends

PQSend will not invent cryptographic algorithms or manually compose low-level
cryptographic primitives. Early versions should use an existing, well-known
backend such as `age` or `rage`. Backend selection requires explicit
specification, threat-model, dependency, and test-vector review.

## DD-004: Encrypted filenames and minimal public metadata

The original filename belongs in the authenticated encrypted internal manifest,
not in public package metadata. Future folder structure, notes, and messages
follow the same rule. Public metadata contains only what is required to
identify, parse, and open a package.

## DD-005: Safe extraction is part of the security boundary

Extraction must treat decrypted metadata as untrusted, prevent path traversal,
and never overwrite an existing file without explicit confirmation. These
behaviors require security-sensitive tests.

## DD-006: Narrow `v0.1` scope

The first package milestone handles exactly one file and one recipient. Folder
support, multiple recipients, signatures, password mode, GUI, relay server, and
chat belong to later milestones with separate design review.

## DD-007: Human-readable security receipts

Receipts are local summaries intended to help users understand recipient
selection and completed safety checks. They are not signatures, proof of
authorship, proof of delivery, or proof of endpoint security.

## DD-008: Backend agility is not current post-quantum protection

Versioned packages and backend identifiers make the design post-quantum-ready
for future migration. PQSend must not claim harvest-now-decrypt-later resistance
until a reviewed hybrid future-resistant backend is implemented and tested.

## DD-009: No stable pre-`v1.0.0` format

Draft package concepts support design discussion and experimental
implementation. They carry no compatibility promise before `v1.0.0`.

## DD-010: Provisional opaque-text contact fingerprints

The first contact book intentionally precedes encryption-backend selection.
Public keys are therefore stored as opaque normalized UTF-8 text, and contacts
use grouped uppercase SHA-256 fingerprints over that normalized text. This
fingerprint is a stable local comparison identifier, not encryption or proof of
identity. Verification is only a deliberate local boolean. The TOML contact
format and fingerprint approach remain experimental and may change when a
reviewed encryption backend is selected.
