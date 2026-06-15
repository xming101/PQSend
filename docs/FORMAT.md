# PQSend Experimental Package Format

> [!WARNING]
> PQSend and the `.pqsend` format are experimental and unaudited. The current
> format is X25519-only, not post-quantum-secure, unstable before `v1.0.0`, and
> not guaranteed to remain compatible between alpha releases. Implementations
> must reject unsupported formats rather than attempting fallback or recovery
> parsing.

This document is the implementer-facing description of the current `.pqsend`
wire format. The only supported wire-format version is version `1`, encoded as
`0x0001`. The product release version and package-format version are separate:
a PQSend product release number does not change how the version field is
interpreted.

The current format contains exactly one file encrypted for exactly one age
X25519 recipient. It does not support folders, multiple files, multiple
recipients, passwords, signatures, notes, or post-quantum encryption.

## Design goals

The current format is designed to provide:

- a portable encrypted package that can be transported by unrelated tools
- a minimal, fixed-size public envelope
- an authenticated encrypted internal manifest
- no original filename in public package metadata
- one canonical encoding with strict byte parsing
- fail-closed handling of malformed, truncated, unsupported, or trailing input

PQSend is a package layer, not a new cryptographic construction. Encryption and
authenticated payload protection are delegated to the Rust `age` backend.

## Encoding conventions

All integers are unsigned and big-endian. All fields are fixed-width except
the encrypted payload, filename, and file body, whose lengths are explicitly
encoded.

There are no flags, reserved bytes, extension fields, implementation-version
fields, timestamps, optional fields, TLV records, archives, JSON, CBOR,
MessagePack, or serde-defined encodings. A future behavior or layout change
requires a new reviewed format version.

All length arithmetic and integer conversions must be checked. EOF must occur
exactly where each layout specifies it.

## Complete package layout

A package is one 20-byte public envelope followed by exactly one complete
binary age v1 encrypted payload:

```text
+----------------------------+------------------------------+
| public envelope (20 bytes) | encrypted payload (N bytes) |
+----------------------------+------------------------------+
```

The complete package size is exactly `20 + N` bytes. No bytes may follow the
declared encrypted payload.

## Public envelope

The public envelope is exactly 20 bytes:

| Offset | Size | Field | Canonical value or rule |
| ---: | ---: | --- | --- |
| 0 | 8 | magic | `89 50 51 53 45 4E 44 0A` (`\x89PQSEND\n`) |
| 8 | 2 | format version | `00 01` (`0x0001`) |
| 10 | 1 | package mode | `01` (`single-file`) |
| 11 | 1 | backend ID | `01` (`age-v1-x25519`) |
| 12 | 8 | encrypted payload length | unsigned big-endian integer in `1..=68,157,749` |
| 20 | declared length | encrypted payload | exactly one complete binary age v1 payload |
| EOF | 0 | trailing data | forbidden |

### Identifier registry

Only these identifiers are currently defined and accepted:

| Field | ID | Meaning |
| --- | ---: | --- |
| format version | `1` | current experimental wire format |
| package mode | `1` | one encrypted file |
| backend | `1` | binary age v1, exactly one X25519 recipient |

Unknown versions, modes, and backends must be rejected. Version `0` is not a
fallback or an unversioned package; it is unsupported.

## Public and encrypted metadata

The public envelope contains only:

- magic
- format version
- package mode
- backend identifier
- encrypted payload length

The following values must not appear as unencrypted package metadata:

- original filename or original path
- contact alias, contact fingerprint, or contact verification status
- sender identity
- note or message
- plaintext file hash
- timestamp

The current format has no original-path, contact, sender-identity, note,
message, or timestamp field anywhere in the package. Contact aliases,
fingerprints, and verification status are local CLI state and are absent from
both the public envelope and encrypted inner plaintext.

The encrypted payload is itself public ciphertext and exposes the use of age
and an X25519 recipient stanza. It must not be treated as opaque padding or as
hiding the selected backend.

## Backend ID 1: age v1 X25519

Backend ID `1` contains one complete binary age v1 file:

- creation encrypts to exactly one age X25519 recipient
- opening accepts exactly one X25519 recipient stanza plus age-permitted GREASE
  stanzas
- ASCII-armored age data is forbidden
- passphrase, SSH, plugin, and multiple-recipient modes are forbidden
- concatenated age files and trailing bytes inside the declared payload are
  forbidden
- complete age authentication must succeed before inner plaintext is exposed
  to the package parser

The current X25519 backend is not post-quantum-secure and does not protect
against quantum attacks against X25519. A future hybrid backend would require a
separately reviewed backend identifier and any necessary format changes.

## Encrypted internal manifest

The age plaintext is one canonical byte string containing the internal
manifest and file body. Its fixed header is 54 bytes:

| Offset | Size | Field | Canonical value or rule |
| ---: | ---: | --- | --- |
| 0 | 8 | inner magic | `50 51 53 49 4E 4E 45 52` (ASCII `PQSINNER`) |
| 8 | 2 | authenticated format version | equals public version (`00 01`) |
| 10 | 1 | authenticated package mode | equals public mode (`01`) |
| 11 | 1 | authenticated backend ID | equals public backend (`01`) |
| 12 | 2 | filename byte length | unsigned big-endian integer in `1..=255` |
| 14 | 8 | file size | unsigned big-endian integer in `0..=67,108,864` |
| 22 | 32 | file hash | raw SHA-256 digest of the exact file body |
| 54 | filename length | original filename | canonical UTF-8 filename bytes |
| after filename | file size | file body | exact file bytes |
| EOF | 0 | trailing data | forbidden |

The authenticated inner copies of version, mode, and backend must exactly
match the public envelope. The declared filename length and file size must
produce exactly the authenticated plaintext length.

The SHA-256 value checks agreement between the authenticated internal metadata
and file body. It is not a substitute for age authentication and must not be
described as an independent authenticity guarantee.

The original filename is encrypted. The original path is not stored.

### Filename requirements

The filename is a filename only, never a path. It must be valid UTF-8 and
between 1 and 255 UTF-8 bytes. Implementations must reject rather than sanitize
a filename that:

- is empty, `.`, or `..`
- contains `/`, `\`, NUL, an ASCII control character, DEL, or any of
  `< > : " | ? *`
- ends with a dot or space
- case-insensitively matches a Windows reserved device stem

Reserved device stems are `CON`, `PRN`, `AUX`, `NUL`, `COM1` through `COM9`,
`LPT1` through `LPT9`, `COM¹`, `COM²`, `COM³`, `LPT¹`, `LPT²`, and `LPT³`.
They remain forbidden when followed by an extension, such as `CON.txt`.

## Canonical creation

A version-1 package writer must:

1. Validate the filename and file-size limits.
2. Compute SHA-256 over the exact file bytes.
3. Encode the canonical inner plaintext in the field order above.
4. Encrypt the complete inner plaintext as one binary age v1 file for exactly
   one X25519 recipient.
5. Reject an empty or oversized encrypted payload.
6. Encode the 20-byte public envelope with the exact encrypted payload length.
7. Append the encrypted payload and no trailing bytes.

Writers must not add fields, padding, reserved bytes, or alternate encodings
under format version `1`.

## Required parsing and opening behavior

A version-1 package reader must perform strict byte parsing and fail closed.
The required validation sequence is:

1. Require at least 20 bytes before reading the public envelope.
2. Validate the exact magic bytes.
3. Reject every format version other than `1`.
4. Reject every package mode other than `1`.
5. Reject every backend other than `1`.
6. Decode the encrypted payload length with checked conversion, reject zero or
   values above `68,157,749`, and use checked addition to compute total size.
7. Require the complete package length to equal `20 + encrypted payload
   length`; reject truncation and trailing outer data.
8. Parse and completely authenticate exactly one supported binary age v1
   payload; reject malformed, truncated, unsupported-mode, concatenated, or
   trailing ciphertext data.
9. Require the authenticated inner plaintext to be at most `67,109,173` bytes
   and at least 54 bytes before reading inner fields.
10. Validate the inner magic and require the inner version, mode, and backend
    to equal the public values.
11. Decode filename length and file size with checked conversions and checked
    addition; enforce all limits.
12. Require the calculated filename and body end to equal the authenticated
    plaintext length; reject missing or trailing inner bytes.
13. Validate the filename and compare the stored SHA-256 value with SHA-256 of
    the exact file body.
14. Return the filename and file bytes only after every check succeeds.

Readers must not use fallback parsing, heuristic recovery, permissive alternate
decodings, or best-effort extraction.

## Error and output behavior

Any malformed, unsupported, unauthenticated, inconsistent, truncated, or
oversized input must cause the entire open operation to fail.

Errors and logs must not contain decrypted filenames, file contents, private
key material, or detailed backend error data. Readers must not return or
publish a filename or any file bytes before complete authentication and
validation.

Filesystem integrations must not publish a partial plaintext file on failure
and must not overwrite an existing destination without explicit confirmation.
The reference core API performs no filesystem writes. The reference CLI opens
and validates the complete package before writing validated plaintext through
a temporary file and publishing the final output without overwrite.

## Exact limits

| Constant | Decimal value | Meaning |
| --- | ---: | --- |
| `FORMAT_VERSION_V1` | 1 | only accepted format version |
| `MODE_SINGLE_FILE` | 1 | only accepted package mode |
| `BACKEND_AGE_V1_X25519` | 1 | only accepted backend |
| `PUBLIC_ENVELOPE_LEN` | 20 | fixed public envelope bytes |
| `MAX_FILENAME_BYTES` | 255 | maximum UTF-8 filename bytes |
| `MAX_FILE_BYTES` | 67,108,864 | maximum file body bytes (64 MiB) |
| `MAX_INNER_METADATA_BYTES` | 309 | 54 fixed bytes plus maximum filename |
| `MAX_INNER_PLAINTEXT_BYTES` | 67,109,173 | maximum metadata plus file body |
| `MAX_ENCRYPTED_PAYLOAD_BYTES` | 68,157,749 | maximum binary age payload |
| `MAX_PACKAGE_BYTES` | 68,157,769 | public envelope plus encrypted payload |

These are format-level acceptance limits, not recommendations to preallocate
untrusted declared lengths.

## Metadata limitations

PQSend does not hide:

- exact encrypted payload and total package sizes
- approximate plaintext size inferred from package size
- use of the age v1 X25519 backend
- the outer `.pqsend` filename selected by the user or transport
- sender, recipient, timing, routing, and other transfer-channel metadata
  outside PQSend

The outer `.pqsend` filename is not part of the package bytes. Naming it after
the original file leaks that name through the filesystem or transport even
though the internal original filename is encrypted.

## Versioning and compatibility

The package-format version is the `u16` value at public-envelope offset 8. It is
separate from the PQSend product version, CLI version, backend version, and
contact-store format.

The current alpha format is unstable. There is no backward- or
forward-compatibility promise before `v1.0.0`, and later releases may reject
packages created by earlier releases. A stable format and compatibility policy
are future targets.

Implementations must reject unknown versions, modes, and backends. They must
not reinterpret an unknown value as the current format or fall back to another
parser.

## Reference implementation

The reference implementation is in:

- `crates/pqsend-core/src/package/envelope.rs`
- `crates/pqsend-core/src/package/single_file.rs`
- `crates/pqsend-core/src/package/mod.rs`
- `crates/pqsend-core/src/backend/age.rs`

Security-sensitive framing and parsing behavior is exercised by
`crates/pqsend-core/tests/package_v01.rs` and
`crates/pqsend-core/tests/age_backend.rs`.

See the [compatibility rules](COMPATIBILITY.md) and
[test-vector index](../test-vectors/README.md) for compatibility policy and
published-vector status.
