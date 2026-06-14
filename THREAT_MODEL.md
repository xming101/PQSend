# Threat Model

## Status and scope

PQSend `v0.1.0-alpha.1` is experimental, unaudited, and must not be used for
sensitive real-world data. The current implementation provides strict
`.pqsend` `v0.1` package creation and opening, a binary age v1 X25519 backend
adapter, an explicit-key-file CLI, and a separate local experimental contact
book. Package behavior is not integrated with contacts. The package format is
unstable and may change incompatibly before `v1.0.0`.

`v0.1` covers one file encrypted locally for exactly one recipient. Folder
support, multiple recipients, signatures, password mode, post-quantum
encryption, GUI, relay server, networking, telemetry, and chat are out of
scope. The implemented v0.1 backend is X25519-only and is not post-quantum
secure.

## Assets

- plaintext file contents and original filenames
- local private key material
- contact public keys and verification status
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

The CLI accepts exactly one explicit X25519 recipient or identity per key file.
It bounds input and package reads, accepts only regular input files, uses only a
validated basename, refuses overwrite, and publishes completed package and
plaintext output files from temporary files. Opening authenticates and
validates the complete package before creating a final plaintext file. It
rejects a symbolic link as the final output-directory component and creates a
missing output directory privately on Unix. Key generation rejects equivalent
destinations, requires existing parent directories, and publishes the public
recipient before the private identity.

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

The separate contact book stores normalized opaque public-key text, a SHA-256
comparison fingerprint, and a manual local `verified` boolean in plaintext
TOML. It is not integrated with package operations. Its fingerprint is not
encryption, a signature, a certificate, or proof of identity, and the verified
flag records only a local user decision.

## Security language and review triggers

PQSend may accurately describe the implemented core as local-first,
single-recipient X25519 package encryption with strict framing. It must not
claim production readiness, post-quantum security, authorship, delivery proof,
or absolute protection.

Update this document, `SPEC.md`, package-format documentation, design
decisions, and security-sensitive tests before changing package behavior,
public metadata, limits, filename policy, extraction rules, cryptographic
dependencies, or protected/not-protected claims.
