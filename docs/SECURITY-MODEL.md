# Security Model

> [!WARNING]
> PQSend is experimental, unaudited, X25519-only, not post-quantum-secure, and
> not ready for sensitive real-world data. The `.pqsend` package format is
> unstable before `v1.0.0`.

This document explains the implemented security design and trust boundaries of
PQSend. It describes design properties, not guarantees. See the
[threat model](THREAT-MODEL.md) for explicit protections, assumptions, and
limitations.

## Design boundary

PQSend is a local package and safety layer around an existing encryption
backend. It does not provide a transfer service and does not require the
transfer channel to be trusted with plaintext.

### Local package creation

Package creation happens on the sender's machine. The reference CLI:

1. Reads one local regular file and validates its size and basename.
2. Resolves either one explicit recipient file or one local contact.
3. Builds the canonical internal manifest and file body in memory.
4. Encrypts the complete internal plaintext for exactly one recipient.
5. Writes the completed `.pqsend` package without overwriting an existing
   destination.

Only the completed encrypted package is intended to be sent through email,
cloud storage, messaging, removable media, or another transfer channel.

### Local package opening

Package opening happens on the recipient's machine. The reference
implementation validates the public envelope and exact package length before
decryption. It then authenticates the complete encrypted payload and validates
the complete internal plaintext before returning or publishing the restored
filename or file bytes.

The CLI rejects unsafe restored filenames, prevents the authenticated filename
from selecting a path outside the chosen output directory, writes through a
temporary file, and refuses implicit overwrite.

### Untrusted transfer channel

PQSend assumes the transfer channel may read, copy, delay, delete, truncate,
replace, or otherwise modify package bytes. The transfer channel is not given
plaintext by PQSend. A recipient must still receive the package bytes and use
the matching private identity locally.

Encryption does not hide transfer-channel metadata such as sender, recipient,
timing, routing, total package size, or the outer package filename.

## Package metadata boundary

### Minimal public envelope

The public package envelope is intentionally minimal and fixed at 20 bytes. It
contains only the package magic, format version, package mode, backend
identifier, and encrypted payload length.

The public envelope reveals that the package uses the current single-file,
age-backed X25519 format and reveals the exact encrypted payload length. The
binary age payload also reveals the use of age and an X25519 recipient stanza.

### Encrypted internal manifest

The internal manifest is encrypted and authenticated as part of the age
plaintext. It contains authenticated copies of the public version, mode, and
backend, plus the original filename, file size, encrypted SHA-256 consistency
value, and exact file bytes.

The SHA-256 value checks agreement between authenticated metadata and the file
body. It is not a replacement for age authentication and is not an independent
authenticity mechanism.

### Original filename

The original filename is hidden from public package metadata because it exists
only inside the encrypted internal manifest. The original path is not stored.

The outer `.pqsend` filename is chosen by the user or transfer system and is
outside this protection. Naming the package after the original file reveals
that name.

## Cryptographic boundary

The current cryptographic backend is age-backed X25519. PQSend delegates
recipient encryption, authenticated payload protection, binary age parsing,
and key handling to the Rust `age` crate through a deliberately narrow
adapter. The current adapter accepts binary age v1 encryption for exactly one
X25519 recipient and opening with exactly one X25519 identity.

PQSend must not invent cryptography, implement low-level cryptographic
primitives, or manually compose them. A backend change requires explicit
design, specification, threat-model, dependency, and test review.

The versioned package envelope and backend identifier are part of a
crypto-agile architecture intended to support a future post-quantum migration
path. A future hybrid backend would require separate review, implementation,
testing, and a defined backend identifier or format change. This architecture
does not make the current X25519 backend post-quantum-secure.

## Contact trust boundary

The contact trust store is local plaintext state. A contact maps a local alias
to one canonical age X25519 recipient and may store a full fingerprint binding
that records local verification of that exact recipient.

For `pack --to <contact>`, the CLI validates the store, resolves one contact,
and passes only its parsed recipient to the package core. Contact aliases,
recipient strings, fingerprints, and verification status are not placed in
the public envelope or encrypted internal manifest.

Unverified contacts are blocked by default. `--allow-unverified` is an
explicit one-command policy override. Verification requires an independent
authenticated comparison of the full fingerprint. It is a local decision, not
identity proof or proof of key control.

See [Contacts](CONTACTS.md) for the contact-store format and operational
limitations.

## Receipt boundary

Security receipts are local user-facing command output. They summarize selected
recipient information, exact observed package hashes, local receipt times, and
completed local checks after successful operations. PQSend does not embed
receipts in `.pqsend` packages or transmit them. Receipt time is local CLI
output, not package metadata or a package creation timestamp.

Receipts are not signatures, authorship proof, identity proof, delivery proof,
or external evidence. Terminal logs and other captured receipt output are
local plaintext metadata.

See [Security Receipts](RECEIPTS.md) for receipt fields and privacy
rules.

## Integrity and extraction

The implemented package reader is designed to reject malformed, tampered,
truncated, unsupported, oversized, or non-canonical packages without returning
partial plaintext. It checks exact outer and inner lengths, complete age
authentication, authenticated public/inner field agreement, filename safety,
and the encrypted file-body hash.

These checks detect invalid package bytes; they do not prevent deletion,
delivery failure, replay, or denial of service. Safe extraction also depends
on the local operating system and filesystem behavior.

## Security dependencies

PQSend's security depends on:

- the sender and recipient machines remaining trustworthy while PQSend runs
- protection of the recipient's private identity key
- correct recipient-key verification
- protection of the local contact store and terminal output
- correctness of PQSend, the Rust `age` crate, SHA-256 implementation, and
  other dependencies
- the operating system random source, memory protections, and filesystem
  behavior

Unknown bugs, dependency vulnerabilities, and future cryptographic breaks
remain possible. The [threat model](THREAT-MODEL.md) lists these and other
explicit non-protections.
