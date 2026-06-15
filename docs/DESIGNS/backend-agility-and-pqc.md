# Backend Agility and Future Hybrid PQC Support

> [!WARNING]
> PQSend is experimental and unaudited. The current backend is X25519-only and
> not post-quantum-secure. The pre-`v1.0.0` format is unstable.

**Status:** future design note; no post-quantum backend is implemented or
selected.

This document describes how PQSend should evaluate and introduce future
encryption backends without making current packages ambiguous or overstating
their security. It is not a wire-format specification, does not assign a new
backend ID, and does not authorize a post-quantum implementation.

The current `.pqsend` package framing, accepted bytes, crypto code, contacts,
and receipt behavior remain unchanged. Canonical implemented behavior is
defined by the [format specification](../FORMAT.md), [security
model](../SECURITY-MODEL.md), [threat model](../THREAT-MODEL.md), and
[compatibility rules](../COMPATIBILITY.md).

## Current backend

PQSend currently supports exactly one encryption backend:

| Backend ID | Label | Payload and recipient profile | PQ status |
| ---: | --- | --- | --- |
| `1` | `age-v1-x25519` | one complete binary age v1 payload for exactly one age X25519 recipient | not post-quantum-secure |

Backend ID `1` is deliberately narrower than "age" in general. It excludes
ASCII armor, passphrases, SSH recipients, plugins, and multiple recipients.
The backend label identifies the complete supported profile rather than only
the underlying X25519 algorithm.

X25519 does not protect against a quantum attacker. Current packages and
receipts must continue to state that they are not post-quantum-secure.
Backend-agility fields create a migration mechanism; they do not add security
to backend ID `1`.

## Backend agility goals

Backend agility should let PQSend migrate cryptography deliberately while
keeping package interpretation exact:

- A `.pqsend` package remains identifiable as a PQSend package across backend
  changes. Its selected backend is an explicit part of that package's
  identity, not an implementation guess.
- Package-format versions, package modes, and backend IDs have separate roles.
  A backend change does not silently redefine an existing identifier.
- Packages created with an older backend remain interpretable from retained
  specifications and test vectors, even if a newer writer no longer selects
  that backend by default.
- Readers either support the package's exact version, mode, and backend tuple
  or reject it as unsupported. They do not negotiate or fall back while
  opening stored package bytes.
- Receipts and inspection output label the selected backend clearly and state
  its reviewed post-quantum status without inference from a product version.
- Migration decisions remain visible and reviewable rather than being hidden
  behind a generic "best available" algorithm choice.

"Interpretable" does not require every future implementation to retain every
obsolete backend forever. It requires that an old package's identifiers keep
one documented meaning and that removal of reader support be an explicit,
documented compatibility decision. Migration tooling, if ever introduced,
must open and validate the old package before creating a distinct new package;
it must not rewrite the meaning of the old package.

## Versioning and package identity

The public tuple `(format version, package mode, backend ID)` identifies how a
package must be parsed and opened. The authenticated inner copies of those
fields bind that public interpretation to the encrypted content.

Each identifier has a distinct purpose:

- The **format version** identifies the public framing and authenticated inner
  grammar, including field meanings, canonical encoding, and limits.
- The **package mode** identifies the content model, such as the current
  single-file mode.
- The **backend ID** identifies the complete encryption payload and recipient
  profile, including the cryptographic construction, required backend
  encoding, supported recipient type or types, authentication behavior, and
  backend-specific acceptance rules.

A new backend may use an existing format version only if the reviewed
specification shows that the public framing, authenticated inner grammar,
field meanings, and applicable limits remain valid without reinterpretation.
A new format version is required whenever those properties change. A new
backend ID is always required when the cryptographic construction, payload
profile, recipient semantics, or backend acceptance rules change.

This design does not change the current fixed-width envelope, assign extension
space, or reserve IDs. Any future format change must be specified separately.

## Future hybrid PQC direction

PQSend should prefer evaluating a reviewed **hybrid classical plus
post-quantum** backend before considering a post-quantum-only migration. A
hybrid design can preserve a classical security component while post-quantum
algorithms and their implementations mature. It also creates explicit room to
analyze downgrade behavior and the consequences of a weakness in either
component.

That preference is a selection principle, not a construction. PQSend must not
design a custom KEM combiner, manually combine shared secrets, or assemble a
new encryption envelope casually. The selected backend should delegate the
hybrid construction, domain separation, key derivation, authenticated
encryption, parsing, and key handling to standardized and reviewed upstream
libraries or protocols with a documented security analysis.

Before a future hybrid backend is selected, its review must define:

- the concrete classical and post-quantum algorithms and parameter sets
- the upstream implementation and its maintenance, audit, and release status
- the hybrid construction's security goals and failure assumptions
- whether both components are required to open a package
- downgrade resistance and behavior when a component is unsupported or
  malformed
- recipient and identity encodings, canonicalization, and size limits
- ciphertext expansion, resource limits, and public metadata exposure
- dependency, interoperability, test-vector, and independent-review plans
- precise claims that receipts and documentation may make

PQSend should avoid a post-quantum-only first migration unless a later review
documents why removing the classical component is preferable and safe for the
project's threat model. Neither "hybrid" nor "post-quantum" alone is evidence
that a construction is secure.

## Backend ID strategy

The backend ID is a one-byte field in the current format, but this design does
not pre-allocate or assign future values. A future backend ID may be assigned
only with a reviewed backend definition and implementation milestone.

Each assigned backend ID must:

- have one immutable, canonical meaning
- name the complete backend profile, not a loose algorithm family
- specify the compatible format versions and package modes
- define exact payload, recipient, identity, parsing, authentication, and
  rejection behavior
- define backend-specific size and resource limits
- document public metadata leakage and security properties
- include an unambiguous human-readable label for inspection and receipts
- include valid and invalid test vectors

IDs must never be reused, aliased, or reinterpreted after publication. A
parameter-set change, construction change, incompatible upstream wire-format
change, or recipient-profile change requires a new backend ID. A library
upgrade that preserves the exact documented profile may retain the ID only
after compatibility and security review.

The canonical format specification should maintain the authoritative backend
ID registry. Supporting documentation may describe the backend in more detail,
but it must not assign a conflicting meaning.

Unknown or unsupported backend IDs must be rejected before backend decryption
is attempted. Readers must not:

- treat an unknown backend as backend ID `1`
- infer a backend from ciphertext bytes or recipient key shape
- try a list of installed backends until one succeeds
- silently substitute a different backend
- downgrade a hybrid package to only its classical component

Errors and inspection output may report the numeric unknown ID, but must not
claim security properties for it.

## Backend documentation and test vectors

Every backend addition must update the canonical format, security model,
threat model, compatibility rules, backend documentation, receipts
documentation, and relevant design decisions before it is described as
supported.

Each backend must have a reviewed vector set covering at least:

- valid packages for every supported format-version and mode combination
- valid canonical recipient and identity representations
- malformed, truncated, oversized, and non-canonical payloads
- wrong identities and failed backend authentication
- unknown and mismatched public and authenticated inner backend IDs
- unsupported recipient profiles and backend modes
- trailing data and ambiguous or alternate encodings
- downgrade attempts relevant to the backend
- cross-version and cross-implementation interoperability

Published valid vectors should remain available with their backend
specifications so old packages stay interpretable. Published invalid vectors
must remain rejected by implementations claiming support for that backend.
Encryption randomness may prevent fresh writers from producing byte-identical
ciphertext, so vector documentation must distinguish fixed snapshots from
semantic interoperability expectations.

## Contacts and recipients

Current contacts contain exactly one canonical age X25519 recipient. Their
recipient type is therefore implicitly limited by the current
`experimental-v1` contact-store format, and current contacts are not
post-quantum-secure.

A future hybrid backend will likely require a new recipient and identity type.
It may also require larger encodings, different fingerprints, or a recipient
that binds classical and post-quantum public material. Those choices belong to
the reviewed backend and contact-store designs; they must not be improvised by
concatenating existing keys.

Future contact state must represent recipient type explicitly. Contact parsing,
canonicalization, fingerprint domain separation, verification bindings, and
display must include that type so the same bytes cannot be interpreted under
different algorithms. Contacts must not assume that one algorithm or recipient
encoding will remain valid forever.

A contact migration must not silently convert or relabel a verified X25519
recipient as hybrid. New recipient material requires an explicit trust
decision and independent verification appropriate to that exact typed
recipient. Whether a contact may hold multiple recipient types, one preferred
type, or a transition set remains an open design question.

Contact aliases, recipient values, fingerprints, and migration state remain
local metadata and must not be added to public package metadata.

## Receipt implications

Receipts must report the exact backend selected by or parsed from the package.
They must also report the backend's documented post-quantum status separately
from the backend label.

For current backend ID `1`, receipts must continue to say:

```text
Backend: age v1 X25519
Post-quantum secure: no
```

Old X25519 package receipts must never imply post-quantum security merely
because they were opened by a newer PQSend release or on a system that also
supports a hybrid backend. Receipt claims derive from the package's exact
backend ID and completed validation, not from installed capabilities, contact
state, defaults, or product branding.

A future backend specification must define the precise receipt label and
permitted PQ-status wording. Until a construction and its claims have been
reviewed, receipts must not label it post-quantum-secure or
harvest-now-decrypt-later resistant. Receipts remain local observations, not
certificates, signatures, or proof that endpoints are secure.

## Compatibility and migration rules

Backend migration must be explicit and fail closed:

- Writers select one documented backend and encode its exact ID.
- Readers dispatch only on a supported version, mode, and backend tuple.
- There is no silent fallback, trial decryption, or algorithm inference.
- An existing backend ID never gains a second meaning.
- Old backend specifications and vectors remain published.
- Deprecation affects writer defaults separately from reader support.
- Removal of reader support requires a documented compatibility decision and
  migration guidance.
- A converted package is a new package with its own identifiers, bytes, hash,
  and receipt; conversion does not upgrade the security history of the source
  package.

Supporting both old and new backends during a transition does not make old
packages post-quantum-secure. Re-encryption can protect the newly created
package under the selected new backend, but cannot undo earlier exposure of
the old ciphertext or plaintext.

## What not to do yet

Until a separate reviewed milestone authorizes implementation, PQSend must
not:

- implement a custom KEM combiner or manually combine classical and
  post-quantum shared secrets
- create a homemade cryptographic envelope or low-level primitive
- add a PQ-only backend merely to claim post-quantum support
- assign a speculative backend ID without a complete specification and vector
  plan
- accept unknown backends or add silent fallback behavior
- relabel or automatically upgrade existing X25519 contacts
- market current packages, backend agility, or an unreviewed future backend as
  post-quantum-secure
- break interpretation of old packages without clear versioning,
  compatibility documentation, and migration guidance

## Open questions

- Which standardized, reviewed upstream hybrid construction and implementation
  best fits PQSend's local package model?
- What exact security claim should a hybrid backend target, and under which
  assumptions about its classical and post-quantum components?
- Can a future hybrid backend reuse the current package-format version without
  changing framing, authenticated inner grammar, limits, or field meanings?
- How should backend-specific payload expansion and resource limits be
  represented and enforced?
- What typed recipient and identity encoding should a hybrid backend use?
- Should a future contact hold one recipient type, multiple independently
  verified recipient types, or an explicit transition bundle?
- How should recipient rotation and migration preserve local trust decisions
  without silently transferring verification?
- What controlled vocabulary should receipts use for hybrid and post-quantum
  status without overstating security?
- How long should implementations retain decryption support for deprecated
  backends, and what migration tooling is safe?
- What interoperability and independent-review threshold is required before a
  future backend becomes a writer default?

See [backend-age.md](../backend-age.md) for the current X25519 adapter and the
[roadmap](../../ROADMAP.md) for milestone ordering.
