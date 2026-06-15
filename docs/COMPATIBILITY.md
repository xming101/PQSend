# Compatibility Rules

> [!WARNING]
> PQSend is experimental, unaudited, X25519-only, not post-quantum-secure, and
> unstable before `v1.0.0`. Pre-v1 releases may intentionally reject packages
> or local state created by other pre-v1 releases.

This document defines the current compatibility policy for the `.pqsend`
format, Rust reference CLI, and experimental local contact store. The canonical
package byte layout and limits are defined in [FORMAT.md](FORMAT.md).

## Package-format compatibility

The package-format version is the unsigned 16-bit value in the public envelope.
It is separate from the PQSend product release, CLI version, Rust crate
version, backend version, and contact-store format.

The current reader and writer support only:

- package-format version `1`
- single-file mode `1`
- backend ID `1`, containing one binary age v1 payload for exactly one X25519
  recipient

Writers must emit the one canonical encoding defined by
[the format specification](FORMAT.md). Readers must reject unknown
identifiers, alternate encodings, malformed or non-canonical input,
unsupported backend modes, truncation, and trailing data. Readers must not
reinterpret unknown values as the current format or attempt fallback or
recovery parsing.

There is no backward- or forward-compatibility promise before `v1.0.0`. A
future release may require an explicit migration tool or may reject an earlier
experimental package version.

## Reference implementation compatibility

`pqsend-core` and `pqsend-cli` are the Rust reference implementation. Their
tests demonstrate intended current behavior, but independent implementations
must follow the documented format and security rules rather than treating
incidental CLI or library behavior as normative.

Product release numbers do not implicitly change package-format identifiers.
A release that changes package framing, accepted encodings, identifiers,
limits, or security-relevant parsing behavior must update the format
specification, compatibility rules, security model, threat model, design
record, and relevant tests.

## Contact-store compatibility

The current local contact-store format is `experimental-v1`. It is separate
from the `.pqsend` package format and is not embedded in package bytes.

Old, unknown, malformed, or incompatible stores are rejected without automatic
migration of recipient trust decisions. An incompatible change may require
contacts to be explicitly re-imported and independently re-verified.

## Test-vector compatibility

The publication layout and current status of package vectors are documented in
[the test-vector index](../test-vectors/README.md). Published valid vectors are
intended to be accepted only by implementations supporting the named
experimental format. Published invalid vectors must be rejected.

No normative cross-implementation vector set has been published yet. Until
vectors are added and reviewed, the canonical format documentation and
security-sensitive Rust tests remain the available compatibility evidence.

## Stability target

A stable `.pqsend` compatibility commitment is a future `v1.0.0` goal. It
requires reviewed canonical encodings, published normative vectors,
interoperability testing, documented migration policy, and security review.
See the [roadmap](../ROADMAP.md) for milestone boundaries.
