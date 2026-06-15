# Threat Model

> [!WARNING]
> PQSend is experimental, unaudited, X25519-only, not post-quantum-secure, and
> not ready for sensitive real-world data. The `.pqsend` package format is
> unstable before `v1.0.0`.

This document describes what the implemented PQSend alpha is designed to
protect and what remains outside its protection. These are scoped design
claims, not absolute guarantees. See the [security model](SECURITY-MODEL.md)
for the design and trust boundaries behind them.

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

## Trust assumptions

PQSend assumes:

- sender and recipient machines, local accounts, and the running PQSend binary
  are trustworthy during use
- users protect private identity keys, local contact state, backups, terminal
  logs, and decrypted output
- users independently compare the authoritative full contact fingerprint
  before recording verification
- the Rust `age` backend, SHA-256 implementation, and other dependencies work
  as documented
- the operating system random source, memory protections, and filesystem
  behavior work correctly

PQSend avoids custom cryptography. The current backend delegates recipient
encryption, authenticated payload protection, binary age parsing, and key
handling to the Rust `age` crate.

## Protected against

Within the scope and assumptions above, PQSend is designed to protect against:

- a cloud, email, messaging, or storage provider reading file contents from a
  correctly created package without the recipient's private identity key
- passive observers reading file contents from package bytes without the
  recipient's private identity key
- accidental package tampering, corruption, or truncation being accepted as a
  valid package
- revealing the original filename through public package metadata
- accidental encryption to an unverified contact when the default contact
  policy blocks it
- malformed, wrong-key, tampered, truncated, unsupported-mode, or
  multiple-recipient age payloads returning partial plaintext
- malformed public or internal framing being accepted
- unsafe decrypted filenames, including path traversal separators and reserved
  device names, being accepted for extraction
- accidental overwrite of existing key, package, or extracted output files
- failed decryption or validation publishing a final plaintext output file

These protections do not make the transfer channel trusted. A channel can
still copy, delay, delete, replace, or refuse to deliver a package.

## Not protected against

PQSend does not protect against:

- malware or compromise on the sender or recipient machine
- a compromised, copied, substituted, or poorly protected private identity key
- a compromised local contact store or local account
- a recipient intentionally leaking plaintext after decryption
- a user choosing a revealing outer `.pqsend` package filename
- exact package size and approximate plaintext-size leakage
- transfer timing, sender, recipient, routing, and other channel metadata
- command-line history, terminal logs, or process inspection revealing local
  aliases, filenames, paths, or key-file locations
- sender anonymity
- authorship proof or signatures
- delivery proof, read receipts, or availability
- identity proof from contact verification
- proof that a recipient currently controls or will protect a private key
- deletion, replay, denial of service, or all resource-exhaustion attacks
- unknown bugs or vulnerabilities in PQSend or its dependencies
- unknown future cryptographic breaks
- quantum attacks against X25519 in the current backend
- filesystem replacement races involving trusted output-directory ancestors
- guaranteed erasure of plaintext from memory, swap, crash dumps, temporary
  storage, filesystem blocks, backups, or debugging tools

The current backend is X25519-only. The crypto-agile architecture provides a
future post-quantum migration path, but no future hybrid backend is currently
implemented or supported.

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

Update this document, the [security model](SECURITY-MODEL.md), `SPEC.md`,
package-format documentation, design decisions, and security-sensitive tests
before changing package behavior, public metadata, limits, filename policy,
extraction rules, cryptographic dependencies, contact trust behavior, receipts,
or protected/not-protected claims.
