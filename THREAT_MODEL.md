# Threat Model

## Status and scope

PQSend is experimental and must not be used for sensitive real-world data yet.
The current code does not encrypt, package, or extract files, so the protections
below are design goals, not claims about a working product.

The `v0.1` threat model covers one file encrypted locally for one recipient and
opened locally from a portable `.pqsend` package. There is no required server.
Folder support, multiple recipients, signatures, password mode, GUI, relay
server, and chat are out of scope.

## Assets

- plaintext file contents and original filenames
- local private key material
- contact public keys and verification status
- package integrity and intended recipient selection
- extracted files and the destination filesystem

## Trust assumptions

- sender and recipient devices are trusted while PQSend operates
- users protect local accounts, backups, and private key material
- users verify contact fingerprints through an independent trusted channel
- the selected existing encryption backend and dependencies work as documented
- the operating system random source and filesystem protections work correctly

PQSend avoids custom cryptography. Early versions should use a reviewed existing
backend such as `age` or `rage` rather than manually composing cryptographic
primitives.

## Protected against

When correctly implemented with a suitable authenticated encryption backend,
the intended design should protect against:

- a cloud, email, messaging, or storage provider reading file contents or the
  original filename from the package
- a passive network observer reading file contents or the original filename
  from the package
- someone stealing the package but not possessing the recipient's private key
- accidental file tampering or corruption going undetected before extraction
- path traversal and extraction outside the selected output directory
- accidental overwrite of an existing file during extraction

If an optional relay server is added later, it must not possess recipient
private keys and therefore must be unable to decrypt file contents.

## Not protected against

PQSend is not intended to protect against:

- malware or compromise on the sender or recipient device
- compromised, copied, or poorly protected private keys
- a recipient leaking plaintext after decryption
- weak, substituted, or unverified contact keys
- metadata such as approximate package size, transfer time, transport sender,
  transport recipient, and other information visible outside the package
- denial of service, package deletion, truncation, or delivery failure
- bugs or vulnerabilities in PQSend, its encryption backend, or dependencies
- unknown future cryptographic breaks
- post-quantum adversaries until a reviewed future-resistant backend is selected
  and implemented

Encryption does not prove who authored a package, that it was delivered, or
that an endpoint was uncompromised. Signatures and receipts must not blur these
distinctions if they are introduced later.

## Metadata limitations

The package design hides the original filename and future folder structure
inside the encrypted payload. It does not promise to hide approximate payload
size, transfer timing, backend-required recipient material, implementation
fingerprints, or metadata exposed by the transport.

## Security language

Accurate descriptions include:

- local-first encryption
- post-quantum-ready, when describing planned backend agility
- hybrid future-resistant, only for a reviewed hybrid backend
- designed to resist harvest-now-decrypt-later attacks, only after such a
  backend is implemented and reviewed
- server cannot decrypt file contents, only when the server lacks private keys
- security depends on correct implementation and private-key protection

Avoid absolute, permanent, or marketing-led security claims. Every claim must
identify the implemented protection and its assumptions or limitations.

## Required review triggers

Update this document and `SPEC.md` before changing package behavior, public
metadata, identity or contact trust, extraction rules, receipts, cryptographic
dependencies, or any protected/not-protected claim.
