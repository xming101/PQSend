# Threat Model

## Status and scope

PQSend `v0.1.0-alpha.1` is experimental, unaudited, and must not be used for
sensitive real-world data. The current implementation provides strict
`.pqsend` `v0.1` package creation and opening, a binary age v1 X25519 backend
adapter, an explicit-key-file CLI, and a local experimental contact book that
can resolve one recipient for package creation. The package format is
unchanged by contact selection and remains unstable before `v1.0.0`.

`v0.1` covers one file encrypted locally for exactly one recipient. Folder
support, multiple recipients, signatures, password mode, post-quantum
encryption, GUI, relay server, networking (including Wi-Fi transfer),
telemetry, and chat are out of scope. The implemented v0.1 backend is
X25519-only and is not post-quantum secure.

## Assets

- plaintext file contents and original filenames
- local private key material
- contact recipients and recipient-bound verification fingerprints
- package integrity and intended recipient selection
- extracted files and destination filesystem

## Trust assumptions

- sender and recipient devices are trusted while PQSend operates
- users protect local accounts, backups, and private key material
- users independently verify intended recipient keys
- the Rust `age` backend, SHA-256 implementation, and dependencies work as
  documented
- the operating system random source and memory protections work correctly

PQSend avoids custom cryptography. Recipient encryption, authenticated payload
protection, binary age parsing, and key handling are delegated to Rust `age`.
SHA-256 is used only inside the encrypted plaintext to verify agreement between
authenticated metadata and file bytes.

## Implemented package boundary

The public parser accepts only the fixed 20-byte `v0.1` envelope, single-file
mode, backend ID 1, a nonzero encrypted length within the documented cap, and
an exact package length with no trailing bytes.

The age adapter accepts exactly one X25519 recipient stanza plus permitted
GREASE stanzas. Decryption authenticates the complete age plaintext in memory
before returning it to package parsing. Package parsing then validates the
inner magic, authenticated copies of version/mode/backend, filename safety,
resource limits, exact body length, absence of trailing bytes, and encrypted
SHA-256 value before returning any filename or contents.

Errors are redacted and do not contain decrypted filenames, file contents, key
material, or detailed backend errors. The core package API accepts and returns
bytes only; it does not access filesystem paths, extract, or overwrite files.

The CLI accepts exactly one explicit X25519 recipient file or one locally
resolved contact for package creation, and exactly one identity per identity
file for opening. Contact packing blocks unverified contacts unless the user
supplies a one-command `--allow-unverified` override. It bounds input and
package reads, accepts only regular input files, uses only a validated
basename, refuses overwrite, and publishes completed package and plaintext
output files from temporary files. Opening authenticates and validates the
complete package before creating a final plaintext file. It rejects a symbolic
link as the final output-directory component and creates a missing output
directory privately on Unix. Key generation rejects equivalent destinations,
requires existing parent directories, and publishes the public recipient
before the private identity.

## Protected against

Within the assumptions above, the implemented core is designed to protect
against:

- package holders without the recipient private key reading file contents,
  the original filename, or the encrypted file hash
- malformed, wrong-key, tampered, truncated, unsupported-mode, or
  multiple-recipient age payloads returning partial plaintext
- malformed public or inner framing being accepted
- unsafe decrypted filenames, including traversal separators and reserved
  Windows device names including superscript-digit aliases, being returned as
  valid package results
- accidental file-body corruption or metadata/body disagreement going
  undetected after authentication
- CLI extraction traversing outside the selected output directory through the
  authenticated filename
- accidental overwrite of existing key, package, or extracted output files
- failed decryption leaving a final plaintext output file
- key-generation validation or public-recipient publication failure leaving an
  unexpected private identity file

## Not protected against

PQSend does not protect against:

- malware or compromise on sender or recipient devices
- compromised, copied, substituted, or poorly protected keys
- a recipient leaking plaintext after decryption
- denial of service, deletion, delivery failure, or all memory-exhaustion
  attacks
- bugs or vulnerabilities in PQSend, age, SHA-256, or dependencies
- filesystem replacement races involving trusted output-directory ancestors
- transport metadata such as sender, recipient, timing, and transfer size
- unknown future cryptographic breaks
- harvest-now-decrypt-later attacks or other post-quantum adversaries
- leakage caused by users naming the outer `.pqsend` package after the
  original plaintext file

Encryption does not prove package authorship, delivery, endpoint security, or
contact identity. The printed local receipts are not signatures or external
proof.

## Metadata limitations

The public envelope reveals that the input is a `.pqsend` `v0.1` single-file
package using the age v1 X25519 backend and reveals the exact encrypted payload
and total package sizes. The binary age payload reveals use of age and the
X25519 stanza type. Approximate plaintext size remains inferable.

The original filename is encrypted inside the package, but the transport's
outer package filename is outside this protection. Naming a package
`original-name.ext.pqsend` leaks that name. Users who want to avoid filename
leakage must choose an outer package name unrelated to the original file.

## Plaintext and resource limitations

Package creation holds the input file, inner plaintext, encrypted payload, and
resulting package in memory at different stages. Opening authenticates the
complete decrypted age plaintext in memory and then returns a validated copy of
the file bytes. The CLI then writes validated plaintext through a temporary file
in the selected output directory before publishing its final name. A failed
write removes the temporary path but cannot guarantee erasure of plaintext disk
blocks. Temporary and in-memory plaintext handling therefore remains a
limitation even with the v0.1 64 MiB (`67,108,864` byte) file cap. Memory or
disk remnants may persist or be exposed by endpoint compromise, swapping, crash
dumps, filesystem behavior, or debugging tools.

The documented caps bound accepted package sizes but do not guarantee
resistance to CPU, allocation, or repeated-input denial of service.

## Contact trust limitations

The separate `experimental-v1` contact book stores canonical age X25519
recipients and optional full fingerprints binding local verification to the
exact recipient. Import and load reject unsupported recipient types, malformed
or non-canonical records, unknown fields, duplicate case-insensitive names,
duplicate recipients, and malformed or mismatched verification fingerprints.
Stored fingerprints and verification status are never trusted without
recomputation.

Verification requires comparison through an independent authenticated channel.
It records a local decision about one exact recipient, not identity proof,
proof of key control, delivery proof, or authorship proof. Short fingerprints
are display-only. Contact names and fingerprints may appear in local CLI output
or receipts but must never enter `.pqsend` package metadata.

The store is plaintext local state used by `pack --to`. Endpoint or
local-account compromise can modify recipients and matching verification
bindings, causing future contact-selected packages to target an attacker key,
replace executable behavior, or observe CLI output. An unverified override is
a deliberate bypass of the local verification policy and provides no extra
assurance. Unix config and store paths reject final-component symlinks and
require private modes; atomic replacement avoids truncating the previous store
before the new store is complete. Contact recipient imports require bounded
regular files, and store type and privacy checks run before bounded store reads.
The 16 KiB recipient-file, 1 MiB store, and 1,024-contact limits reduce but do
not eliminate allocation or parsing denial of service. These checks do not
eliminate filesystem race conditions against an attacker controlling the local
account. Windows does not yet enforce equivalent ACL privacy and has
platform-dependent replacement semantics.

Contact selection is a CLI-only operation. The package core receives only an
`AgeRecipient`; contact names, full or short fingerprints, and verification
status are not included in the public envelope or encrypted manifest.

## Security language and review triggers

PQSend may accurately describe the implemented core as local-first,
single-recipient X25519 package encryption with strict framing. It must not
claim production readiness, post-quantum security, authorship, delivery proof,
or absolute protection.

Update this document, `SPEC.md`, package-format documentation, design
decisions, and security-sensitive tests before changing package behavior,
public metadata, limits, filename policy, extraction rules, cryptographic
dependencies, or protected/not-protected claims.
