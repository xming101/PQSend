# Threat Model

> [!WARNING]
> PQSend is experimental, unaudited, X25519-only, not post-quantum-secure, and
> not ready for sensitive real-world data. The `.pqsend` package format is
> unstable before `v1.0.0`.

This document describes what the implemented PQSend alpha is designed to
protect and what remains outside its protection. These are scoped design
claims, not absolute guarantees. See the [security model](SECURITY-MODEL.md)
for the design and trust boundaries behind them, the [format
specification](FORMAT.md) for the canonical package bytes, and the [project
README](../README.md) for the current project scope.

## Scope

The current implementation creates one `.pqsend` package locally for exactly
one age X25519 recipient and opens it locally with exactly one X25519 identity.
It includes a strict single-file package format, a local contact trust store,
and local user-facing receipts.

Folders, multiple recipients, signatures, password mode, post-quantum
encryption, GUI, networking, relay services, telemetry, and chat are outside
the current scope.

## Assets

PQSend aims to protect:

- plaintext file contents
- the original filename stored inside a package
- recipient private identity key material
- local contact recipients and recipient-bound verification state
- package integrity and intended recipient selection
- extracted files and the selected output directory

## Adversaries considered

The model considers:

- a cloud, email, messaging, or storage provider that can read package bytes
- a passive observer who obtains package bytes
- a transfer channel or package holder that modifies, truncates, replaces, or
  appends package bytes
- accidental corruption of package bytes
- accidental use of an unverified local contact when the default policy blocks
  it

The model assumes the sender and recipient endpoints are not compromised while
PQSend operates.

## Assumptions

PQSend assumes:

- sender and recipient machines, local accounts, and the running PQSend binary
  are trustworthy during use
- users protect their private identity keys, local contact state, backups,
  terminal logs, and decrypted output
- recipient public keys are obtained correctly before use, whether supplied
  through an explicit recipient file or selected from a local contact
- users independently compare the authoritative full contact fingerprint
  before recording verification
- the Rust `age` backend behaves correctly, and the SHA-256 implementation and
  other dependencies work as documented
- the operating system random source, memory protections, and filesystem
  operations behave as expected

PQSend avoids custom cryptography. The current backend delegates recipient
encryption, authenticated payload protection, binary age parsing, and key
handling to the Rust `age` crate.

## In-scope threats

Within the scope and assumptions above, PQSend is designed to address:

- an untrusted transfer channel or passive package holder attempting to read
  file contents without the recipient's private identity key
- accidental plaintext original-filename leakage inside the package bytes
- a tampered or corrupted package being accepted as valid
- a truncated package being accepted or partially opened
- use of the wrong private key returning trusted or partial plaintext
- malformed parser input, unsupported identifiers, alternate encodings, or
  trailing data being accepted
- a restored filename causing path traversal or selecting a path outside the
  chosen output directory
- unsafe decrypted filenames, including reserved device names, being accepted
  for extraction
- accidental encryption to an unverified local contact when the default
  contact policy blocks it
- accidental overwrite of existing key, package, or extracted output files
- failed decryption or validation publishing a final plaintext output file

These protections do not make the transfer channel trusted. A channel can
still copy, delay, delete, replace, or refuse to deliver a package.

Public inspection is limited to the fixed public envelope and exact outer
length checks. It requires no private identity, does not decrypt or
authenticate the encrypted payload, fails closed on unsupported identifiers
and malformed outer framing, and does not expose encrypted manifest fields or
plaintext contents. Successful inspection explicitly warns about visible
package size and outer filenames and the current backend's lack of
post-quantum security.

## Out-of-scope threats

PQSend does not protect against:

- a compromised sender or recipient endpoint
- a stolen, copied, substituted, compromised, or poorly protected private key
- a malicious recipient retaining or disclosing plaintext after decryption
- local malware
- compromise of the local contact store or local account
- traffic analysis, including transfer timing, sender, recipient, routing, and
  other channel metadata
- exact package-size and approximate plaintext-size leakage
- leakage caused by a revealing outer `.pqsend` package filename
- shell history, terminal logs, or process inspection revealing local aliases,
  filenames, paths, or key-file locations
- a quantum attacker against current X25519 packages
- legal compulsion
- sender anonymity
- authorship proof or signatures
- delivery proof, read receipts, or availability
- identity proof from contact verification
- proof that a recipient currently controls or will protect a private key
- deletion, replay, denial of service, or all resource-exhaustion attacks
- unknown bugs or vulnerabilities in PQSend or its dependencies
- unknown future cryptographic breaks
- filesystem replacement races involving trusted output-directory ancestors
- guaranteed erasure of plaintext from memory, swap, crash dumps, temporary
  storage, filesystem blocks, backups, or debugging tools

The current backend is X25519-only. The crypto-agile architecture provides a
future post-quantum migration path, but no future hybrid backend is currently
implemented or supported.

## Current limitations

- PQSend and the `.pqsend` package format are experimental and unaudited.
- The current backend is X25519-only and is not post-quantum-secure.
- The package format and compatibility policy are unstable before `v1.0.0`.
- Conservative file, plaintext, encrypted-payload, and package-size limits
  bound normal parser allocation and work but do not prevent all
  resource-exhaustion attacks.
- Contact verification is local recipient-key comparison through an
  independent authenticated channel. It is not identity proof, proof of key
  control, or protection against contact-store compromise.

## Contact-specific risks

Contacts are local convenience aliases for canonical recipient keys. They do
not form an identity system or trusted directory.

- An unverified contact can contain the wrong or an attacker-controlled key.
- Verification requires comparison of the full fingerprint through an
  independent authenticated channel.
- Compromise of the local contact store can replace recipient keys and matching
  verification bindings.
- Short fingerprints are display-only and must not be used for verification or
  duplicate decisions.
- Contact verification records a local decision about one exact recipient. It
  is not identity proof, proof of key control, authorship proof, or delivery
  proof.
- `--allow-unverified` deliberately bypasses the default local verification
  policy for one command.
- Explicit recipient-file packing does not consult contact verification.

Contact aliases and verification outcomes may appear in local pack receipts.
Recipient strings and fingerprints may appear in explicit contact-command
output, and full fingerprints appear in blocked unverified-contact errors, but
they are omitted from successful pack receipts. None are included in the
public envelope or encrypted internal manifest.

Receipts also expose the observed package path and SHA-256, a local receipt
time, and, after opening, the restored output path. Terminal capture can retain
those fields as local plaintext metadata. Receipt fields are not cryptographic
proof or cryptographic certificates and do not establish package creation time,
identity, authorship, or delivery.

## Package and metadata limits

The public envelope reveals the package format version, single-file mode,
age-backed X25519 backend, and exact encrypted payload length. The encrypted
age payload also reveals the use of age and an X25519 recipient stanza.

The original filename is encrypted inside the package, but the outer package
filename is outside the package bytes. Users must choose an unrelated outer
filename when revealing the original name would be sensitive.

PQSend does not pad packages to hide file size. Approximate plaintext size is
inferable from total package size.

## Integrity and parsing limits

The public parser accepts only the fixed 20-byte current envelope, single-file
mode, current backend, a bounded nonzero encrypted length, and an exact package
length with no trailing bytes.

Opening authenticates the complete age plaintext before package parsing returns
any filename or file contents. Package parsing then validates the internal
magic, authenticated copies of public fields, filename safety, resource limits,
exact body length, absence of trailing bytes, and the encrypted SHA-256
consistency value.

These checks are designed to detect and reject invalid packages. They do not
prove who created a package, when it was created, whether it was delivered, or
whether it is the newest package.

## Plaintext and resource limits

Package creation and opening hold plaintext and ciphertext buffers in memory at
different stages. The CLI writes validated plaintext through a temporary file
before publishing its final name. Failed writes remove the temporary path but
cannot guarantee erasure of plaintext disk blocks or other remnants.

The current 64 MiB file limit and related package limits bound normal package
allocation and parsing work. They do not guarantee resistance to CPU,
allocation, repeated-input, or storage denial of service.

## Review triggers

Update this document, the [security model](SECURITY-MODEL.md), canonical
[format specification](FORMAT.md), [compatibility rules](COMPATIBILITY.md),
design decisions, and security-sensitive tests before changing package
behavior, public metadata, limits, filename policy, extraction rules,
cryptographic dependencies, contact trust behavior, receipts, or
protected/not-protected claims.

See also [local contacts and recipient trust](CONTACTS.md), [local security
receipts](RECEIPTS.md), and the [test-vector index](../test-vectors/README.md).
