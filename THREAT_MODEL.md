# Threat Model

## Status and scope

This is an initial threat model for the intended PQSend design. The current code
does not encrypt, package, or extract files, so the protections below are goals,
not claims about a working product.

PQSend is intended for users who exchange portable `.pqsend` files over
untrusted transport while performing all sensitive operations locally.

## Assets

- plaintext file contents and filenames
- local private key material
- contact public keys and verification state
- package integrity and recipient selection
- extracted files and the destination filesystem

## Trust assumptions

- sender and recipient devices are trusted at the time of local operation
- users verify contact fingerprints through an independent trusted channel
- selected cryptographic libraries and the operating system random source work
  as documented
- users protect local accounts, backups, and private key material

## Protected against

The intended mature design should protect against:

- an untrusted transport reading plaintext file contents
- an untrusted transport learning plaintext filenames from package contents
- undetected modification of encrypted package contents
- accidental overwrite of existing files during extraction
- path traversal and extraction outside the selected output directory
- unnecessary disclosure through public package metadata

## Not protected against

PQSend is not intended to protect against:

- compromised sender or recipient devices
- malware, keyloggers, screen capture, or memory inspection on an endpoint
- traffic analysis, including package size, timing, sender, recipient, or
  transport metadata visible outside the package
- denial of service, package deletion, truncation, or delivery failure
- a user accepting the wrong contact key or skipping independent verification
- disclosure after a recipient decrypts, copies, or shares a file
- weaknesses in future dependencies or cryptographic constructions
- post-quantum adversaries until a reviewed post-quantum milestone exists

## Current non-goals

The initial milestones exclude networking, relay services, GUI, password mode,
signatures, chat, and post-quantum cryptography.

## Required review triggers

Update this document and `SPEC.md` before changing package behavior, public
metadata, identity or contact trust, extraction rules, dependencies used for
cryptography, or any protected/not-protected claim.
