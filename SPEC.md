# PQSend Draft Specification

## Status

This document defines the draft `.pqsend` `v0.1` package concept. It is
experimental, non-normative, incomplete, and unstable. There is no compatibility
promise before `v1.0.0`, and implementations must fail closed on unknown or
malformed input.

No encryption or package serialization is implemented in the repository. The
experimental local contact book described below is implemented, but it is not
part of a `.pqsend` package format.

## Product boundary

PQSend is an opinionated encrypted file-sending package layer for humans. It is
not a new cryptographic construction and does not claim stronger cryptography
than its backend.

Early versions should delegate recipient encryption and authenticated payload
protection to an existing, well-known backend such as `age` or `rage`. PQSend
must not manually compose low-level cryptographic primitives.

The `v0.1` scope is exactly one file encrypted for one recipient. Folder
support, multiple recipients, signatures, password mode, GUI, relay server, and
chat are out of scope.

## Experimental local contact book

PQSend stores contacts in `contacts.toml` below an OS-appropriate local config
directory. Approximate default directories are:

| Platform | Config directory |
| --- | --- |
| Linux | `~/.config/pqsend/` |
| macOS | `~/Library/Application Support/pqsend/` |
| Windows | `%APPDATA%\pqsend\` |

The contact store format is experimental and unstable. It contains a format
marker and a list of contacts. Each contact contains a case-sensitive local
name, normalized public key text, fingerprint, and local verified boolean. A
representative record is:

```toml
format = "experimental-v0"

[[contacts]]
name = "Alice"
public_key = "opaque public key text"
fingerprint = "ABCD EFGH ..."
verified = false
```

Public keys are opaque UTF-8 text. The contact book does not validate a
cryptographic key format and does not generate keys or sender identities. On
import, PQSend:

1. reads the selected file as UTF-8 text
2. converts CRLF and CR line endings to LF
3. trims leading and trailing whitespace
4. rejects the result if it is empty
5. otherwise preserves the internal text

The fingerprint is SHA-256 over the UTF-8 bytes of the normalized public key
text. It is displayed as stable uppercase hexadecimal in four-character
groups. This fingerprint is only a contact identifier. SHA-256 fingerprinting
is not encryption, and the fingerprint does not prove control of a key or a
person's identity.

Contact names contain 1 to 64 ASCII letters, numbers, `_`, `-`, or `.`
characters. Names must not start with `.`, contain `..`, separators,
whitespace, control characters, or other characters. Names are matched exactly
and case-sensitively. Duplicate names are rejected; contact replacement is not
implemented.

`pqsend init` creates the directory and contact store without overwriting an
existing store. `pqsend contact verify` changes only the local `verified`
boolean. It is a deliberate manual trust flag, not automated verification,
trust-on-first-use, a signature, or a certificate.

## Goals

A draft `.pqsend` `v0.1` package should:

- be a portable single-file container
- be created and opened locally without telemetry or a required server
- encrypt one file's contents and original filename for one recipient
- expose only the public metadata required to identify and open the package
- detect accidental corruption or tampering before extraction
- extract without path traversal or implicit overwrite

## Conceptual package structure

A `v0.1` package conceptually contains:

1. a small public envelope used to identify, parse, and dispatch the package
2. backend-specific recipient material required to open the encrypted payload
3. one authenticated encrypted payload containing:
   - an encrypted internal manifest
   - the single encrypted file body

The exact byte layout, encoding, framing, limits, and backend choice remain
undecided. The encrypted payload may be embedded, but the public envelope still
needs an unambiguous payload location or framing rule.

## Public envelope

The public envelope may include only fields required for package processing:

| Field | Purpose |
| --- | --- |
| format name | identifies the input as a PQSend package |
| format version | selects the package parser and compatibility behavior |
| implementation version | optional diagnostic identifier |
| package mode | identifies `single-file` mode in `v0.1` |
| backend identifier | selects the reviewed encryption backend |
| encrypted payload location | locates or frames the encrypted payload |

The backend may require public cryptographic recipient material. That material
must be limited to what the backend requires and reviewed for metadata impact.

The public envelope must not include:

- the plaintext original filename
- a plaintext folder or source path
- a plaintext note or message
- a plaintext recipient display name by default
- user-supplied descriptions or comments

Transport observers can still learn metadata outside or inherent to the
package, including approximate package size and transfer time. An optional
implementation version can also aid implementation fingerprinting.

## Encrypted internal manifest

The authenticated encrypted payload must contain an internal manifest with:

| Field | Requirement |
| --- | --- |
| original filename | required; a filename only, never a source folder path |
| file size | required; used for validation and resource limits |
| file hash | required; supports validation and human-readable receipts |
| creation timestamp | optional; include only when a defined use justifies the metadata |
| note or message | reserved for a future milestone; not used by `v0.1` |

The manifest and file body must be protected together by the selected
authenticated encryption backend. The file hash is not a replacement for
backend authentication.

## Opening and extraction

An opener must authenticate package data before trusting the internal manifest
or writing output. It must:

- reject unknown versions, modes, backends, and malformed framing
- enforce documented resource limits before allocation and extraction
- treat the manifest filename as an untrusted filename, not a path
- reject absolute paths, separators, parent traversal, unsafe platform names,
  and other path forms that could escape the selected output directory
- reject conflicting output paths
- never overwrite an existing file without explicit confirmation
- avoid exposing decrypted filenames or contents in logs or receipts by default

## Security receipts

A security receipt is a future local, human-readable summary of checks and
choices made during an operation. It is not part of the public package envelope
and is not a signature, proof of authorship, or proof of delivery. Receipt
behavior is deferred beyond `v0.1`.

## Compatibility and change policy

All pre-`v1.0.0` formats are experimental and unstable. A package format change
requires corresponding updates to this document, `THREAT_MODEL.md`, design
rationale, test vectors, and security-sensitive tests before implementation is
complete.
