# PQSend Draft Specification

## Status

This document defines the experimental `.pqsend` `v0.1` package format used by
`v0.1.0-alpha.1`. The package format is unstable before `v1.0.0`; pre-v1
releases may change it incompatibly and there is no backward-compatibility
promise. Implementations must fail closed on unknown, malformed,
non-canonical, or oversized input.

The repository implements this format in `pqsend-core` and exposes it through a
narrow CLI using either an explicit age X25519 recipient file or a locally
resolved contact. The CLI does not implement folders, multiple recipients,
signatures, password mode, post-quantum encryption, GUI, networking (including
Wi-Fi transfer), relay services, telemetry, or chat.

The canonical implementer-facing wire-format description is
`docs/FORMAT.md`.

## Product and cryptographic boundary

PQSend is a package and safety layer, not a new cryptographic construction. The
`v0.1` package delegates recipient encryption and authenticated payload
protection to the Rust `age` crate and contains exactly one complete binary age
v1 encrypted payload for exactly one X25519 recipient. Decryption accepts
exactly one X25519 recipient stanza plus age-permitted GREASE stanzas.

X25519 is not post-quantum-secure. SHA-256 inside the encrypted plaintext checks
that authenticated metadata and file bytes agree; it is not authentication and
does not replace age authentication.

## Numeric encoding and canonical parsing

All integers are unsigned big-endian. All fields are fixed width except the
filename and file body, whose lengths are explicit. There are no flags,
reserved bytes, extension fields, implementation versions, timestamps, JSON,
CBOR, MessagePack, serde encoding, TLV records, archives, or optional fields.

All arithmetic and integer conversions must be checked. Parsers must reject
truncation, impossible lengths, unknown values, and trailing bytes. Decrypted
filenames and contents must not appear in errors or logs. No partial plaintext
may be returned after any validation failure.

## Public envelope

The public envelope is exactly 20 bytes:

| Offset | Size | Field | Canonical value or rule |
| ---: | ---: | --- | --- |
| 0 | 8 | magic | `89 50 51 53 45 4E 44 0A` (`\x89PQSEND\n`) |
| 8 | 2 | format version | `0x0001` |
| 10 | 1 | package mode | `0x01` (`single-file`) |
| 11 | 1 | backend ID | `0x01` (binary age v1, one X25519 recipient) |
| 12 | 8 | encrypted payload length | `1..=68,157,749` |
| 20 | variable | encrypted payload | exactly the declared number of bytes |

EOF must immediately follow the encrypted payload. The encrypted payload must
be exactly one complete binary age file; ASCII armor and trailing data are
forbidden.

The public envelope contains no flags, reserved bytes, header length,
implementation version, timestamp, extension field, recipient display name,
recipient key, sender identity, note, plaintext filename, plaintext path, or
plaintext file hash.

## Encrypted inner plaintext

Age encrypts one canonical plaintext with this exact layout:

| Offset | Size | Field | Canonical value or rule |
| ---: | ---: | --- | --- |
| 0 | 8 | inner magic | ASCII `PQSINNER` |
| 8 | 2 | authenticated format version | equals public version |
| 10 | 1 | authenticated package mode | equals public mode |
| 11 | 1 | authenticated backend ID | equals public backend |
| 12 | 2 | filename byte length | `1..=255` |
| 14 | 8 | file size | `0..=67,108,864` |
| 22 | 32 | file hash | raw SHA-256 of exact file bytes |
| 54 | variable | filename | exact canonical UTF-8 filename bytes |
| after filename | variable | file body | exactly `file size` bytes |

EOF must immediately follow the file body. The inner/public version, mode, and
backend values are compared only after successful age authentication. The
inner plaintext contains no source path, timestamp, note, folder entry, or
other optional metadata.

## Filename rules

The filename is a filename only, never a path. Implementations reject rather
than sanitize a filename that:

- is not UTF-8, is empty, is `.`, or is `..`
- exceeds 255 UTF-8 bytes
- contains `/`, `\`, NUL, an ASCII control character, or any of
  `< > : " | ? *`
- ends with a dot or space
- case-insensitively matches a Windows reserved device stem: `CON`, `PRN`,
  `AUX`, `NUL`, `COM1` through `COM9`, `LPT1` through `LPT9`, `COM¹`,
  `COM²`, `COM³`, `LPT¹`, `LPT²`, or `LPT³`

Reserved device stems remain forbidden when followed by an extension, such as
`CON.txt`.

## Limits

| Constant | Value | Meaning |
| --- | ---: | --- |
| `FORMAT_VERSION_V1` | 1 | only accepted version |
| `MODE_SINGLE_FILE` | 1 | only accepted mode |
| `BACKEND_AGE_V1_X25519` | 1 | only accepted backend |
| `PUBLIC_ENVELOPE_LEN` | 20 | fixed public bytes |
| `MAX_FILENAME_BYTES` | 255 | maximum UTF-8 filename bytes |
| `MAX_FILE_BYTES` | 67,108,864 | maximum file body bytes |
| `MAX_INNER_METADATA_BYTES` | 309 | 54 fixed bytes plus filename |
| `MAX_INNER_PLAINTEXT_BYTES` | 67,109,173 | metadata plus file body |
| `MAX_ENCRYPTED_PAYLOAD_BYTES` | 68,157,749 | maximum binary age payload |
| `MAX_PACKAGE_BYTES` | 68,157,769 | envelope plus encrypted payload |

`MAX_FILE_BYTES` is the v0.1 file-size limit: 64 MiB (`67,108,864` bytes).

Package opening validates the public envelope and exact outer length before age
decryption. After complete age authentication, it validates the complete inner
plaintext, filename, exact body length, and SHA-256 value before returning a
filename or file bytes. The core API operates only on in-memory bytes and does
not write or overwrite files.

## CLI filesystem behavior

The v0.1 CLI uses explicit key files and local contacts:

- `keygen` creates one age X25519 identity file and its matching public
  recipient file without overwriting either destination. It rejects equivalent
  destination paths, requires both parent directories to already exist, and
  publishes the public recipient before the private identity so a failed
  operation does not leave an unexpected private key.
- `pack` accepts one regular file of at most `MAX_FILE_BYTES`, encrypts only its
  validated UTF-8 basename, requires exactly one of `--recipient-file` or
  `--to <contact>` plus an output package path, and publishes the completed
  package without overwriting. `--allow-unverified` is valid only with `--to`.
  Explicit recipient-file packing does not consult contact verification.
- `open` requires an explicit identity file and output directory. It
  authenticates and validates the complete package before restoring the
  filename, writes through a temporary file in the output directory, and
  publishes it without overwriting. The final output-directory component must
  not be a symbolic link. A newly created output directory is private on Unix.
- `inspect` validates and displays only fields from the public envelope plus
  total package size. It does not decrypt the package.

Recipient and identity files must each contain exactly one unadorned age X25519
key, with optional comments. SSH, plugin, passphrase, armor, and other key or
ciphertext modes are unsupported. The CLI prints local security receipts to
standard output after successful `pack` and `open` operations. Receipts explain
the `.pqsend` format version, single-file mode, age v1 X25519 backend,
not-post-quantum-secure status, selected completed checks, the observed package
path and SHA-256, and a local receipt time explicitly labeled as not package
metadata. They warn that PQSend is experimental, unaudited, and uses an
unstable format. Opening also warns that sender identity and authorship are not
verified. Receipts are not cryptographic certificates, are not embedded in
packages, and are not printed by `inspect`.

## Experimental local contact book

The separate experimental contact book stores contacts in `contacts.toml`
below an OS-appropriate local config directory. It is not integrated with
package opening. For `pack --to <contact>`, the CLI resolves exactly one
validated runtime contact and passes only its parsed `AgeRecipient` to the
unchanged package API. The incompatible store format is
`experimental-v1`; `experimental-v0` and unknown formats are rejected without
automatic migration. Users must explicitly re-import and re-verify old
contacts.

Each serialized contact contains only:

```toml
name = "Alice"
recipient_type = "age-x25519"
recipient = "<canonical age X25519 recipient>"
verified_fingerprint = "<optional full fingerprint>"
```

Unknown fields and malformed records reject the entire store. Raw imported
text, comments, whitespace, source filenames, generic fingerprints, and
independent verification booleans are not stored. Import accepts exactly one
age X25519 recipient and stores its canonical parse-and-reserialize form. It
rejects empty or malformed input, identities, SSH and plugin recipients,
passphrase modes, post-quantum recipients, and multiple keys. Recipient import
requires a regular UTF-8 file no larger than 16 KiB.

The full fingerprint is:

```text
pqsend-contact-v1:hex(SHA-256(
  "pqsend-contact-fingerprint-v1\0age-x25519\0" || canonical_recipient
))
```

Hexadecimal output is lowercase. The short fingerprint is the first 96 bits of
the same digest and is display-only; it is never used for verification or
duplicate decisions. Stored verification is valid only when
`verified_fingerprint` exactly matches the recomputed full fingerprint.
Malformed or mismatched stored verification rejects the entire store.
`contact verify` displays the canonical recipient and full fingerprint and
requires exact full-fingerprint confirmation.

Contact names contain 1 to 64 ASCII letters, numbers, `_`, `-`, or `.`
characters and reject separators, traversal forms, whitespace, and controls.
Capitalization is preserved for display, while lookup and uniqueness are
ASCII-case-insensitive. Duplicate canonical recipients are rejected. Contact
replacement and aliases are not implemented.

Verification requires comparison through an independent authenticated channel.
It is not a signature, certificate, identity proof, proof of key control,
delivery proof, or authorship proof. Local contact-store compromise can change
recipients and verification bindings. Contact names and fingerprints may
appear in explicit contact-command output and blocked unverified-contact
errors. Contact aliases and verification outcomes may appear in successful
local pack receipts. None of these values may be included in `.pqsend` package
metadata.

`pack --to <contact>` blocks an unverified contact by default and reports the
contact name, full fingerprint, and verification instruction. The
`--allow-unverified` flag permits an explicit one-command override, reports the
override in local output, and does not alter stored verification. A successful
contact pack receipt displays the local contact source, contact alias,
verification outcome, and any explicit unverified override. It does not print
the contact fingerprint or recipient string. None of those values are supplied
to package framing or the encrypted inner manifest.

Writes use a completed same-directory temporary file and atomic rename without
first truncating the existing store. On Unix, the final config directory and
store must be non-symlinks, must be a directory and regular file respectively,
and must have modes `0700` and `0600`. Type and privacy checks occur before
store contents are read and again after the bounded read. Contact stores are
limited to 1 MiB and 1,024 contacts. Windows currently lacks equivalent ACL
privacy enforcement, and atomic replacement behavior is platform-dependent.
The store does not currently use an exclusive lock, so concurrent writers can
lose updates.

The original filename is encrypted inside the package, but an outer `.pqsend`
filename chosen by the user or transport remains public metadata. Users who
want to avoid filename leakage must not name the outer package after the
original file.

## Compatibility and change policy

A package-format or security-boundary change requires corresponding updates to
this document, `docs/FORMAT.md`, `docs/design-decisions.md`,
`docs/SECURITY-MODEL.md`, `docs/THREAT-MODEL.md`, the top-level
`THREAT_MODEL.md` summary, and security-sensitive tests before implementation
is complete.
