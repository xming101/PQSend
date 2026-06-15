# Design Decisions

> [!WARNING]
> PQSend is experimental, unaudited, X25519-only, not post-quantum-secure, and
> unstable before `v1.0.0`.

This log records decisions that shape multiple parts of PQSend. It is not a
substitute for the canonical [format specification](FORMAT.md),
[security model](SECURITY-MODEL.md), [threat model](THREAT-MODEL.md), or
[compatibility rules](COMPATIBILITY.md).

## DD-001: Local-first portable packages

PQSend creates portable `.pqsend` files that can be transported by unrelated
tools. Encryption and decryption happen locally. PQSend has no telemetry and
does not require or currently provide a network service.

## DD-002: A package layer, not stronger cryptography

PQSend's role is an opinionated, human-oriented package and safety layer. It is
not an `age` replacement and does not claim stronger cryptography than its
selected backend. The package layer provides encrypted internal metadata,
contacts and verification status, security receipts, and safe defaults.

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

Versioned packages and backend identifiers are part of a crypto-agile
architecture intended to support a future post-quantum migration path. PQSend
must not claim current post-quantum protection. A future hybrid backend requires
separate review, implementation, and testing.

## DD-009: No stable pre-`v1.0.0` format

Draft package concepts support design discussion and experimental
implementation. They carry no compatibility promise before `v1.0.0`.

## DD-010: Canonical X25519 contacts and recipient-bound verification

The hardened contact book accepts exactly one recipient through the narrow age
X25519 backend adapter and stores only its canonical parse-and-reserialize
form. The incompatible `experimental-v1` TOML format rejects old stores,
unknown fields, malformed records, non-canonical recipients, duplicate
case-insensitive names, duplicate recipients, and invalid verification
bindings.

Full fingerprints are domain-separated and versioned:
`pqsend-contact-v1:hex(SHA-256("pqsend-contact-fingerprint-v1\0age-x25519\0" ||
canonical_recipient))`. Short fingerprints are the first 96 bits and are
display-only. Verification stores the recomputed full fingerprint rather than
an independent boolean, so it is bound to the exact recipient. Verification
still records only a deliberate local comparison through an independent
authenticated channel; it is not identity proof, proof of key control,
delivery proof, or authorship proof.

Store updates use same-directory temporary files and atomic replacement. Unix
paths must be non-symlinks with private `0700`/`0600` modes, checked before
bounded store reads. Recipient files are limited to 16 KiB, and stores are
limited to 1 MiB and 1,024 contacts. No locking is currently used, so
concurrent writers can lose updates. Windows ACL privacy and atomic replacement
guarantees remain limitations.

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
into the same output name. Requiring a canonical safe filename keeps v0.1
single-file extraction predictable and prevents the authenticated name from
selecting a path outside the chosen output directory.

## DD-013: Contacts resolve only at the CLI package boundary

`pack --to <contact>` resolves one validated local contact to its parsed
`AgeRecipient`, then calls the unchanged package API with only that recipient.
The package core does not receive the contact name, fingerprint, or
verification status. Consequently contact selection does not change the
public envelope or encrypted inner manifest.

Verified contacts pack by default. Unverified contacts fail with their full
fingerprint and verification instructions unless the user explicitly supplies
`--allow-unverified`; that override affects only the current command and is
reported in local output. Explicit `--recipient-file` packing remains
independent of the contact store.
