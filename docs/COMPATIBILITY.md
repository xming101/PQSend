# Compatibility and Versioning Rules

> [!WARNING]
> PQSend is experimental, unaudited, X25519-only, not post-quantum-secure, and
> unstable before `v1.0.0`. Pre-v1 releases may intentionally reject packages
> or local state created by other pre-v1 releases.

This document defines the compatibility and versioning policy for the
experimental `.pqsend` format and Rust reference CLI. The canonical package
bytes, encodings, identifiers, and limits are defined in
[FORMAT.md](FORMAT.md).

## Compatibility status

The current v0 alpha format is unstable. There is no long-term backward- or
forward-compatibility guarantee before `v1.0.0`. A pre-v1 release may make an
incompatible format change, require an explicit migration tool, or reject
packages created by an earlier alpha release. Such changes must be clearly
documented.

The published [test vectors](../test-vectors/README.md) define current
reference behavior for their named experimental vector set. They support
interoperability testing, but do not create a pre-v1 stability promise.

## Version identifiers

Product release versions and the following identifiers are separate:

| Identifier | Current value | Compatibility role |
| --- | --- | --- |
| package-format version | `1` | Selects the complete `.pqsend` wire-format rules. It is the unsigned 16-bit value in the public envelope. |
| package mode | `1` (`single-file`) | Selects the package content model within the format version. |
| backend ID | `1` (`age-v1-x25519`) | Selects the cryptographic backend payload rules. |
| contact-store format | `experimental-v1` | Versions local reference-CLI contact state. It is not part of a `.pqsend` package. |
| receipt output | unversioned, human-readable, unstable | Describes local CLI output only. It is not a stable machine-readable API or package identifier. |

The current v0 alpha product releases write package-format version `1`. A
product release number, CLI version, Rust crate version, backend library
version, or contact-store format does not implicitly select or change a
package-format identifier.

## Parser rules

Readers and public-envelope inspectors must fail closed. For every supported
format, parsers must:

- reject unknown or unsupported format versions
- reject unknown or unsupported package modes
- reject unknown or unsupported backend IDs
- reject malformed, invalid, overflowing, truncated, or inconsistent lengths
- reject trailing bytes wherever the selected format requires exact EOF
- never guess a fallback parser or use heuristic recovery
- never silently reinterpret a package mode or backend as another supported
  value
- reject alternate or non-canonical encodings unless a future format
  explicitly documents them

Version `0` is not an unversioned fallback. Unknown identifiers are not
extension points that a parser may ignore. Complete backend authentication and
all inner validation must succeed before a reader returns or publishes a
plaintext filename or file bytes.

## Writer rules

Writers for a supported format must follow [FORMAT.md](FORMAT.md) exactly.
They must:

- emit only the canonical encoding for the selected version, mode, and backend
- follow the documented field order, identifier values, lengths, and limits
- not add undocumented fields, flags, padding, reserved bytes, or alternate
  encodings
- not leak hidden metadata, including the original filename, into the public
  envelope
- terminate each structure exactly where the format requires, without trailing
  bytes

A new field or encoding must not be placed into an existing identifier's
layout. It requires reviewed and documented versioning decisions before any
implementation writes it.

## Test-vector compatibility

The [test-vector index](../test-vectors/README.md) documents the publication
layout and current status of the vector corpus:

- valid vectors define packages or structures that implementations supporting
  the named experimental format are expected to accept
- invalid vectors define malformed, unsupported, or non-canonical inputs that
  those implementations are expected to reject

Future implementations should use both sets to test strict parsing,
interoperable opening, expected restored results, and rejection behavior.
Implementations should not expect newly encrypted output to reproduce fixed
ciphertext snapshots byte-for-byte because encryption uses randomness.

The current [`v0-alpha` vector set](../test-vectors/v0-alpha/README.md) defines
the current Rust reference behavior for package-format version `1`, mode `1`,
and backend ID `1`. Its test identities and recipient keys are deliberately
public fixtures only. They must never be used for real secrets.

Vectors and expectations may change incompatibly before `v1.0.0`. A future
compatibility claim requires reviewed valid and invalid vectors for the
claimed behavior.

## Backend agility

The backend ID separates the package's format and mode identity from the
cryptographic backend payload rules. The only current backend is backend ID
`1`: one binary age v1 payload for exactly one X25519 recipient.

The current age v1 X25519 backend is not post-quantum-secure. Backend agility
does not make current packages resistant to quantum attacks.

A future reviewed hybrid post-quantum cryptography backend may be added later
under documented format, security, threat-model, migration, identifier, and
test-vector rules. It must use a distinct documented backend ID and any
required new format or mode identifiers. Readers must reject unknown backends;
they must never reinterpret one backend's payload as another backend.

## Stability milestones

- **v0 alpha:** experimental implementation and format behavior; no stable
  compatibility commitment
- **v0.x:** format exploration, parser hardening, migration-policy work, and
  interoperability testing; documented incompatible changes remain possible
- **v1.0:** first possible stable `.pqsend` compatibility target, contingent
  on review, canonical encodings, normative vectors, interoperability testing,
  and documented migration policy

Pre-v1 formats may break with clear documentation. A stable compatibility
commitment must be stated explicitly; it is not implied by the existence of a
format version or test corpus.

## Reference CLI compatibility

`pqsend-core` and `pqsend-cli` are the Rust reference implementation. Their
tests demonstrate intended current behavior, but independent implementations
must follow the documented format and security rules rather than incidental
CLI or library behavior.

CLI commands, wording, formatting, error messages, and user experience may
change before `v1.0.0`. Package compatibility and strict parser behavior matter
more than reproducing exact CLI output.

## Contact-store compatibility

The reference CLI's local contact-store format is `experimental-v1`. It is
separate from the `.pqsend` package format and is never embedded in package
bytes.

Old, unknown, malformed, or incompatible stores are rejected without automatic
migration of recipient trust decisions. An incompatible store change may
require contacts to be explicitly re-imported and independently re-verified.

## Receipt compatibility

Current receipts are unversioned, local, human-readable reference-CLI output.
Their wording, field order, and formatting are unstable and are not a
machine-readable compatibility API. Package compatibility does not require
independent implementations to reproduce exact receipt output.

A future stable machine-readable receipt interface would require an explicitly
versioned schema plus documented privacy, security, and compatibility rules.
It must not be inferred from current receipt text.

## Change requirements

A release that changes package framing, accepted encodings, identifiers,
limits, or security-relevant parsing behavior must update the canonical format
specification, compatibility rules, security model, threat model, relevant
test vectors, and security-sensitive tests. Compatibility claims must not rely
only on permissive behavior observed in one implementation.

## Related documents

- [Project overview](../README.md)
- [Canonical package format](FORMAT.md)
- [Security model](SECURITY-MODEL.md)
- [Security receipts](RECEIPTS.md)
- [Test vectors](../test-vectors/README.md)
- [Roadmap](../ROADMAP.md)
- [Changelog](../CHANGELOG.md)
