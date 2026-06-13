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

## DD-011: Narrow Rust age X25519 backend adapter

The experimental `v0.1` backend delegates cryptographic operations and parsing
to the Rust `age` crate. It uses age's public identity policy hook and
`age-core` stanza types only to enforce the supported recipient boundary. The
adapter is limited to binary age v1 encryption for exactly one X25519 recipient
and decryption with exactly one X25519 identity. It does not shell out to `age`
or `rage`, implement custom cryptography, or expose plugins, SSH keys,
passphrases, ASCII armor, or multiple-recipient encryption. Decryption rejects
headers that do not contain exactly one X25519 recipient stanza plus the age
format's permitted GREASE stanzas, and returns plaintext only after complete
authentication.

The `age` crate is pre-`1.0`, so the adapter remains experimental. X25519 is not
post-quantum-secure; future-resistant backend work requires a separate review.
This decision selects the encryption backend adapter. Package framing is
defined separately by DD-012.

## DD-012: Strict fixed-width v0.1 package framing

The `v0.1` package uses a fixed 20-byte public envelope and one fixed-order
encrypted single-file plaintext. Unsigned big-endian fixed-width fields make
the canonical byte representation and parser boundaries obvious. The format
does not use serde, JSON, CBOR, MessagePack, archives, or TLV records because
`v0.1` has no need for a general serialization system or optional fields.

There are no flags or reserved bytes. Reserving unauthenticated extension space
would add parsing and downgrade ambiguity before a concrete reviewed use
exists. A future behavior change must use a new reviewed format version.

Only single-file mode and the binary age v1 one-X25519-recipient backend are
accepted. This keeps the parser and security boundary aligned with implemented
behavior rather than implying unsupported flexibility.

The 255-byte filename limit, 64 MiB file limit, and derived inner, encrypted,
and total-package caps bound normal allocation and parsing work. They do not
eliminate denial-of-service risk, but they replace unbounded package-level
memory use with a conservative experimental ceiling.

Filenames are rejected rather than sanitized. Sanitization can silently change
the authenticated name, create collisions, or turn different hostile inputs
into the same output name. Requiring a canonical safe filename keeps any
future filesystem extraction decision explicit.
