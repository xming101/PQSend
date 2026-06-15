# PQSend Experimental Package Format

This document is the sole source of truth for the currently implemented
`.pqsend` package byte format. It specifies package-format version `1`, encoded
as `0x0001`, as implemented by the Rust reference CLI and core library.

Product release versions and package-format versions are separate. The current
`v0.1` alpha product milestone writes package-format version `1`.

## Format status

> [!WARNING]
> PQSend and the `.pqsend` format are experimental and unaudited. The format is
> unstable before `v1.0.0` and is not guaranteed to remain compatible between
> alpha releases. The current alpha uses age-backed X25519 and is not
> post-quantum-secure.

The current format contains exactly one file encrypted for exactly one age
X25519 recipient. It does not support folders, multiple files, multiple
recipients, passwords, signatures, notes, or post-quantum encryption.

## Design goals

The current format is designed to provide:

- a portable encrypted package that unrelated tools can transport
- minimal public metadata in a fixed-size public envelope
- an authenticated encrypted internal manifest
- local recipient trust decisions that do not become package metadata
- safe public inspection without decrypting or exposing private metadata
- compatibility behavior defined by canonical bytes, strict parsing, and test
  vectors
- future backend agility through explicit version, mode, and backend IDs

Backend agility is a future migration mechanism, not a current security
property. It does not make backend ID `1` post-quantum-secure.

## File extension

PQSend packages use the `.pqsend` file extension. The extension identifies the
intended file type but is not part of the package bytes and is not validated by
the package parser.

The outer package filename is selected by the user or transfer system. It is
not encrypted by PQSend.

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

The public envelope contains no flags, padding, optional fields, or reserved
bytes.

### Identifier registry

Only these identifiers are currently defined and accepted:

| Field | ID | Meaning |
| --- | ---: | --- |
| format version | `1` | current experimental wire format |
| package mode | `1` | one encrypted file |
| backend | `1` | binary age v1, exactly one X25519 recipient |

Version `0` is not an unversioned fallback. Unknown versions, modes, and
backends are unsupported and must be rejected.

## Current mode

Mode ID `1` is the only implemented package mode. It contains exactly one
encrypted filename and one encrypted file body.

Folders, paths, multiple files, and archive entries are not represented by
mode ID `1`. They are future plans and must not be encoded under this mode.

## Current backend

Backend ID `1` is age v1 X25519. Its encrypted payload is one complete binary
age v1 file:

- creation encrypts to exactly one age X25519 recipient
- opening accepts exactly one X25519 recipient stanza plus age-permitted GREASE
  stanzas
- ASCII-armored age data is forbidden
- passphrase, SSH, plugin, and multiple-recipient modes are forbidden
- concatenated age files and trailing bytes inside the declared payload are
  forbidden
- complete age authentication must succeed before inner plaintext is exposed
  to the package parser

The current age-backed X25519 backend is not post-quantum-secure and does not
protect against quantum attacks against X25519. A future hybrid or
post-quantum backend requires separate review, a distinct backend identifier,
and any necessary format changes.

## Encrypted payload

The bytes after the public envelope are the complete binary age payload for
backend ID `1`. The age plaintext is the complete inner plaintext structure
defined below.

The encrypted payload therefore protects and authenticates:

- the internal manifest, including the original filename, file size, and file
  hash
- authenticated copies of the public version, mode, and backend
- the exact file bytes

The age payload is public ciphertext. It exposes the use of age, an X25519
recipient stanza, and its exact length. It is not padding and does not hide the
selected backend.

## Inner plaintext structure

The age plaintext is one canonical byte string containing the internal
manifest followed by the file body. The complete byte string is encrypted as
the age payload. Its fixed header is 54 bytes:

| Offset | Size | Field | Canonical value or rule |
| ---: | ---: | --- | --- |
| 0 | 8 | inner magic | `50 51 53 49 4E 4E 45 52` (ASCII `PQSINNER`) |
| 8 | 2 | authenticated format version | equals public version (`00 01`) |
| 10 | 1 | authenticated package mode | equals public mode (`01`) |
| 11 | 1 | authenticated backend ID | equals public backend (`01`) |
| 12 | 2 | filename byte length | unsigned big-endian integer in `1..=255` |
| 14 | 8 | file size | unsigned big-endian integer in `0..=67,108,864` |
| 22 | 32 | file hash | raw SHA-256 digest of the exact file body |
| 54 | filename length | original filename | valid UTF-8 bytes satisfying the filename rules |
| after filename | file size | file body | exact file bytes |
| EOF | 0 | trailing data | forbidden |

The authenticated inner copies of version, mode, and backend must exactly
match the public envelope. The declared filename length and file size must
produce exactly the authenticated plaintext length.

The SHA-256 value checks agreement between authenticated internal metadata and
the file body. It is not a substitute for age authentication, a signature, or
an independent authenticity guarantee.

## Filename rules

The original filename is encrypted inside the inner plaintext. The source path
is not stored anywhere in the package.

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

Rejecting rather than sanitizing prevents different authenticated filenames
from being silently rewritten to the same output name.

## Size limits

The current `v0.1` alpha accepts file bodies up to 64 MiB. All related caps are
implemented and are format-level acceptance limits:

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

The encrypted payload length in the public envelope is a `u64`, but values
outside `1..=68,157,749` are invalid. These limits are not recommendations to
preallocate untrusted declared lengths.

## Canonical creation

A package-format version `1` writer must:

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

## Validation rules

A package-format version `1` reader must perform strict byte parsing and fail
closed. It must reject:

- a package shorter than the 20-byte public envelope
- bad public magic
- unsupported or unknown format versions, including version `0`
- unsupported or unknown package modes
- unsupported or unknown backend IDs
- a zero, oversized, unrepresentable, or otherwise invalid encrypted payload
  length
- any mismatch between the declared encrypted payload length and complete
  package length, including truncation or trailing outer data
- malformed, truncated, unsupported-mode, concatenated, unauthenticated, or
  trailing binary age payload data
- an inner plaintext shorter than 54 bytes or larger than `67,109,173` bytes
- bad inner magic
- any mismatch between authenticated inner and public version, mode, or backend
- a zero, oversized, invalid UTF-8, or unsafe filename
- an oversized file body
- impossible inner lengths, missing bytes, or trailing inner data
- a file body whose SHA-256 does not match the encrypted inner hash

Readers must use checked conversions and checked length arithmetic. They must
not use fallback parsing, heuristic recovery, permissive alternate decodings,
or best-effort extraction.

No filename or file bytes may be returned or published before backend
authentication and every inner validation check succeeds.

## Safe public inspection

Public inspection may parse only the public envelope and verify that the
complete package length exactly matches its declared encrypted payload length.
It can report the `.pqsend` format label, fixed public-envelope length,
public-envelope parseability, format version, package mode, backend ID and
label, encrypted payload length, total package size, exact package-length
agreement, and absence of trailing bytes without a recipient identity.

Inspection must fail closed on bad magic, unsupported public version, mode, or
backend identifiers, invalid declared lengths, truncation, and trailing outer
data. Unsupported identifiers may be reported as rejected public values, but
inspection must not attempt fallback parsing.

Public inspection does not authenticate or decrypt the age payload and must not
claim that the package will open successfully. It must not expose the original
filename, file contents, encrypted file hash, recipient key, local contact
name, contact fingerprint, contact verification status, sender identity, or
encrypted internal-manifest fields. Inspection output warns that the original
filename and internal manifest remain encrypted, contents require decryption,
the current X25519-only backend is not post-quantum-secure, and package size
and the outer filename remain visible.

## Metadata leakage

Package holders and transfer systems can observe:

- exact encrypted payload length and total package size
- approximate plaintext size inferred from package size
- format version, package mode, and backend ID
- use of age and an X25519 recipient stanza
- the outer `.pqsend` filename
- transfer timing, sender, recipient, routing, and other channel metadata

The original filename, exact file size, file hash, and file bytes are inside
the encrypted payload. The original filename is not public package metadata,
but choosing an outer package filename based on it leaks that name outside the
format.

Contact names, recipient fingerprints, and contact verification status are
local trust state. They are not metadata in the public envelope or encrypted
inner plaintext.

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

## Compatibility behavior

The package-format version is the `u16` value at public-envelope offset 8. It
is separate from the PQSend product version, CLI version, backend version, and
contact-store format.

Readers fail closed. Unknown IDs and alternate encodings are rejected, and
there is no fallback parser. The current alpha format has no backward- or
forward-compatibility promise before `v1.0.0`; later releases may reject
packages created by earlier alpha releases.

Future framing, identifier, limit, or parsing changes require updates to this
document, the compatibility and security documentation, and relevant tests.
Compatibility claims require reviewed valid and invalid test vectors. No
normative cross-implementation vector set has been published yet.

See the [compatibility rules](COMPATIBILITY.md) and
[test-vector index](../test-vectors/README.md).

## Non-goals

The current `.pqsend` format is not:

- an age replacement
- a messaging application or chat protocol
- a cloud transfer protocol or relay protocol
- a signature or authorship format
- post-quantum-secure
- a folder, archive, multiple-recipient, password, note, or message format

These capabilities must not be inferred from the current framing. Any that are
considered later are future plans requiring separate design and security
review.

## Reference implementation

The reference implementation is in:

- `crates/pqsend-core/src/package/envelope.rs`
- `crates/pqsend-core/src/package/single_file.rs`
- `crates/pqsend-core/src/package/mod.rs`
- `crates/pqsend-core/src/backend/age.rs`

Security-sensitive framing and parsing behavior is exercised by
`crates/pqsend-core/tests/package_v01.rs` and
`crates/pqsend-core/tests/age_backend.rs`.
