# `.pqsend` v0.1 Package Format

The experimental `v0.1` format is a strict binary container for one file
encrypted to one age X25519 recipient. It has one 20-byte public envelope
followed by exactly one complete binary age v1 file. The format is unstable and
may change incompatibly before `v1.0.0`. It is not extensible: unknown values,
malformed lengths, and trailing bytes are rejected.

All integers are unsigned big-endian. Every arithmetic operation and integer
conversion is checked.

## Complete outer layout

| Offset | Size | Bytes or range | Meaning |
| ---: | ---: | --- | --- |
| 0 | 8 | `89 50 51 53 45 4E 44 0A` | magic `\x89PQSEND\n` |
| 8 | 2 | `00 01` | format version 1 |
| 10 | 1 | `01` | single-file mode |
| 11 | 1 | `01` | binary age v1 with one X25519 recipient |
| 12 | 8 | `00 00 00 00 00 00 00 01` through the encoded maximum | encrypted payload byte length |
| 20 | declared length | binary age data | exactly one complete encrypted payload |
| EOF | 0 | none | trailing bytes forbidden |

The public envelope is always exactly 20 bytes. It deliberately includes no
flags, reserved bytes, header length, implementation version, timestamp,
extensions, recipient name or key, sender identity, note, filename, path, or
file hash.

Opening rejects a package shorter than 20 bytes, bad magic, version zero,
unknown versions/modes/backends, zero or excessive encrypted lengths, any
outer-length mismatch, trailing bytes, and age authentication or mode failure.

## Complete inner layout

The binary age plaintext is one canonical byte string:

| Offset | Size | Bytes or range | Meaning |
| ---: | ---: | --- | --- |
| 0 | 8 | `50 51 53 49 4E 4E 45 52` | ASCII `PQSINNER` |
| 8 | 2 | `00 01` | authenticated version, equal to public version |
| 10 | 1 | `01` | authenticated mode, equal to public mode |
| 11 | 1 | `01` | authenticated backend, equal to public backend |
| 12 | 2 | `00 01` through `00 FF` | filename byte length |
| 14 | 8 | zero through `67,108,864` | file body byte length |
| 22 | 32 | raw bytes | SHA-256 of the exact file body |
| 54 | filename length | canonical UTF-8 | original filename only |
| after filename | file size | raw bytes | exact file body |
| EOF | 0 | none | trailing inner bytes forbidden |

The complete encrypted plaintext is authenticated before inner fields are
trusted. The inner version, mode, and backend must match the public envelope.
The declared filename and file sizes must produce exactly the authenticated
plaintext length. The SHA-256 value is encrypted consistency metadata, not an
authentication mechanism.

## Filename rejection

Filenames are accepted only as UTF-8 byte strings of 1 through 255 bytes.
PQSend rejects rather than sanitizes `.`, `..`, separators, NUL, ASCII control
characters including DEL, Windows-forbidden characters `< > : " | ? *`,
trailing dots, trailing spaces, and Windows reserved device stems.

Reserved device matching is case-insensitive and covers `CON`, `PRN`, `AUX`,
`NUL`, `COM1` through `COM9`, `LPT1` through `LPT9`, `COM¹`, `COM²`, `COM³`,
`LPT¹`, `LPT²`, and `LPT³`, including names with an extension such as
`con.txt`.

## Exact limits

| Constant | Decimal value |
| --- | ---: |
| `FORMAT_VERSION_V1` | 1 |
| `MODE_SINGLE_FILE` | 1 |
| `BACKEND_AGE_V1_X25519` | 1 |
| `PUBLIC_ENVELOPE_LEN` | 20 |
| `MAX_FILENAME_BYTES` | 255 |
| `MAX_FILE_BYTES` | 67,108,864 |
| `MAX_INNER_METADATA_BYTES` | 309 |
| `MAX_INNER_PLAINTEXT_BYTES` | 67,109,173 |
| `MAX_ENCRYPTED_PAYLOAD_BYTES` | 68,157,749 |
| `MAX_PACKAGE_BYTES` | 68,157,769 |

The metadata maximum is `54 + 255`. The inner maximum is `309 + 67,108,864`.
The package maximum is `20 + 68,157,749`.
The v0.1 file-size limit is 64 MiB (`67,108,864` bytes).

## Scope and privacy

The core creates and opens package bytes in memory. The v0.1 CLI wraps that core
with explicit X25519 key files or local contact resolution, single-file package
creation, authenticated extraction, and public-envelope inspection. Contact
resolution passes only an `AgeRecipient` into the core. Contact names, full or
short fingerprints, and verification status are absent from both the public
envelope and encrypted inner plaintext. Folder entries, multiple recipients,
password mode, signatures, post-quantum encryption, padding, notes, timestamps,
and extension fields are absent.

The original filename and SHA-256 value are encrypted. Approximate package size
and the fact that age/X25519 is used remain visible. Users who want to avoid
filename leakage must not name the outer `.pqsend` package after the original
file.
