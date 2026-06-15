# Security Receipts

> [!WARNING]
> PQSend is experimental, unaudited, X25519-only, not post-quantum-secure, and
> unstable before `v1.0.0`.

PQSend receipts are local, human-readable status summaries printed by the Rust
reference CLI after successful `pack` and `open` operations. They explain the
completed local action and selected format- and security-relevant facts, such
as the package mode, encryption backend, recipient source, and validation
results.

Receipts help a user understand how the reference CLI created or opened a
package. They describe the CLI's local observations and checks; they do not add
properties to the package or replace the [security model](SECURITY-MODEL.md)
and [threat model](THREAT-MODEL.md).

## What receipts are not

Receipts are not:

- cryptographic certificates
- signatures or proof of authorship
- security audits or audit reports
- proof of delivery or receipt by another party
- proof of identity or current key control
- package creation timestamps or trusted external evidence
- records embedded in or transmitted with `.pqsend` packages
- a stable machine-readable API

The current receipt text is intended for people. Scripts must not treat its
wording, field order, or formatting as a stable interface. A future
machine-readable interface would require an explicitly versioned schema.

## Storage and privacy boundary

Receipts are printed to standard output. PQSend does not embed them in the
public envelope, encrypted internal manifest, or any other part of a `.pqsend`
package.

Receipt output follows these privacy rules:

- never print private keys
- never print decrypted file contents
- never embed contact names, contact fingerprints, or verification state into
  packages
- omit recipient keys and contact fingerprints from successful pack receipts
- allow local terminal output to show a local contact alias and verification
  outcome when that context was used

Terminal capture, shell logging, or manually saved output can retain receipt
fields as local plaintext metadata. Pack receipts show the package path.
Contact-backed pack receipts also show the local contact alias and verification
outcome. Open receipts show the restored output path and therefore reveal the
decrypted original filename to the local terminal.

The receipt time is generated from the local system clock after the successful
operation. It is labeled `Local receipt time (Unix seconds; not package
metadata)` because it is neither authenticated package metadata nor a package
creation timestamp.

## Pack receipt

A successful `pack` receipt reports:

- action: package created
- format: `.pqsend`
- format version: `1`
- package mode: single file
- public envelope: fixed 20-byte v0.1 envelope
- backend: age v1 X25519
- post-quantum status: not post-quantum-secure
- original filename hidden from package metadata: yes
- encrypted internal manifest: yes
- recipient source: explicit recipient file or local contact
- contact verification: verified, unverified override, or not applicable
- local contact alias, when a local contact was selected
- package path and SHA-256 of the completed package bytes
- local receipt time, explicitly labeled as not package metadata
- known public leakage: package size, transfer timing, and outer package
  filename
- experimental, unaudited, unstable-format warning

Contact verification status records local contact-store state at creation time.
It does not establish identity or key control. An unverified contact is blocked
unless the user explicitly supplies `--allow-unverified`; the receipt then
reports that one-operation override prominently.

Example using an explicit recipient file:

```text
Security receipt (local CLI output only)
Action: package created
Format: .pqsend
Format version: 1
Package mode: single file
Public envelope: fixed 20-byte v0.1 envelope
Backend: age v1 X25519
Post-quantum secure: no
Original filename hidden in package metadata: yes
Internal manifest encrypted: yes
Recipient source: explicit recipient file
Contact verification: not applicable
Package path: transfer-001.pqsend
Package SHA-256: <SHA-256 of exact package bytes>
Local receipt time (Unix seconds; not package metadata): <local Unix time>
Known public leakage: package size, transfer timing, outer package filename
Reminder: transfer channel does not need to be trusted with plaintext
Warning: experimental, unaudited, unstable format
```

Because the unverified-contact override is implemented, a contact-backed pack
receipt may instead include:

```text
Recipient source: local contact
Contact alias: Bob
Contact verification: unverified override
WARNING: unverified contact override used for this operation only
```

The override does not mark the contact verified and does not change package
framing or encryption behavior.

## Open receipt

A successful `open` receipt reports:

- action: package opened
- format: `.pqsend`
- format version: `1`
- package mode: single file
- backend: age v1 X25519
- post-quantum status: not post-quantum-secure
- decryption success: yes
- backend authentication and integrity verification: yes
- inner manifest validation: yes
- original filename restoration: yes
- restored output path
- package path and SHA-256 of the opened package bytes
- local receipt time, explicitly labeled as not package metadata
- explicit notice that sender identity and authorship are not verified
- experimental, unaudited, unstable-format warning

Example:

```text
Security receipt (local CLI output only)
Action: package opened
Format: .pqsend
Format version: 1
Package mode: single file
Backend: age v1 X25519
Post-quantum secure: no
Decryption succeeded: yes
Integrity verified by backend authentication: yes
Inner manifest validated: yes
Original filename restored: yes
Output path: opened/report.pdf
Package path: transfer-001.pqsend
Package SHA-256: <SHA-256 of exact package bytes>
Local receipt time (Unix seconds; not package metadata): <local Unix time>
Sender identity and authorship verified: no; PQSend does not implement signatures
Warning: experimental, unaudited, unstable format
```

## Inspect versus receipts

`inspect` and receipts serve different purposes:

- `inspect` parses only the public envelope and reports public package metadata:
  fixed envelope length and parseability, format version, package mode, backend
  ID and label, encrypted payload length, total package size, exact declared
  length agreement, and absence of trailing bytes. It also states that hidden
  fields remain encrypted and warns about the X25519-only backend and visible
  outer size and filename. It does not decrypt, authenticate, extract, require
  a private identity, or print a receipt.
- receipts describe local action context after a successful `pack` or `open`,
  including recipient-selection context for packing and completed validation
  checks for opening.

Neither interface is a browser for hidden package metadata. `inspect` must
never reveal it. Receipts do not dump the encrypted internal manifest or
decrypted contents. A successful `open` receipt does show the restored output
path, including the restored filename, because that is local action context
after authorized decryption and validation.

## Interpreting the package hash

The package SHA-256 identifies the exact package bytes observed locally. It can
help compare two local copies and debug accidental changes. It does not prove
who created the package, whether it was delivered, or whether a separately
communicated hash is trustworthy.

## Future possibilities

PQSend does not currently implement structured receipts, signed receipts, or a
machine-readable receipt schema. These are future possibilities only. Any such
feature would require explicit design, versioning, privacy and security review,
documentation, and tests before it could be described as implemented.

Signed receipts would not be added implicitly to the current package format
and must not be inferred from current receipt output.

## Related documents

- [Project overview](../README.md)
- [Package format](FORMAT.md)
- [Security model](SECURITY-MODEL.md)
- [Threat model](THREAT-MODEL.md)
- [Contacts and local recipient trust](CONTACTS.md)
