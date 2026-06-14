# PQSend Draft Specification

## Status

This document defines the experimental `.pqsend` `v0.1` package format used by
`v0.1.0-alpha.1`. The package format is unstable before `v1.0.0`; pre-v1
releases may change it incompatibly and there is no backward-compatibility
promise. Implementations must fail closed on unknown, malformed,
non-canonical, or oversized input.

The repository implements this format in `pqsend-core` and exposes it through a
narrow CLI using explicit age X25519 key files. The CLI does not integrate the
contact book or implement folders, multiple recipients, signatures, password
mode, post-quantum encryption, GUI, networking, relay services, telemetry, or
chat.

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

The v0.1 CLI uses only explicit key files:

- `keygen` creates one age X25519 identity file and its matching public
  recipient file without overwriting either destination. It rejects equivalent
  destination paths, requires both parent directories to already exist, and
  publishes the public recipient before the private identity so a failed
  operation does not leave an unexpected private key.
- `pack` accepts one regular file of at most `MAX_FILE_BYTES`, encrypts only its
  validated UTF-8 basename, requires an explicit recipient file and output
  package path, and publishes the completed package without overwriting.
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
standard output; receipts are not embedded in packages.

## Experimental local contact book

The separate experimental contact book stores contacts in `contacts.toml`
below an OS-appropriate local config directory. It is not integrated with
package creation or opening. Contacts contain a case-sensitive local name,
normalized opaque public-key text, a SHA-256 comparison fingerprint, and a
local manual `verified` boolean.

The fingerprint is not encryption, a signature, a certificate, or proof of
identity. Contact names contain 1 to 64 ASCII letters, numbers, `_`, `-`, or
`.` characters and reject separators, traversal forms, whitespace, controls,
and duplicates. Contact replacement is not implemented.

The original filename is encrypted inside the package, but an outer `.pqsend`
filename chosen by the user or transport remains public metadata. Users who
want to avoid filename leakage must not name the outer package after the
original file.

## Compatibility and change policy

A package-format or security-boundary change requires corresponding updates to
this document, `docs/package-format.md`, `docs/design-decisions.md`,
`THREAT_MODEL.md`, and security-sensitive tests before implementation is
complete.
