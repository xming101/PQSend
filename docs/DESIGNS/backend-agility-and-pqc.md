# Backend Agility and Post-quantum Evaluation

**Status:** future design note; no post-quantum backend is implemented or
selected.

The current `.pqsend` format and Rust reference implementation support only
backend ID `1`: one binary age v1 payload for exactly one X25519 recipient.
X25519 is not post-quantum-secure, so current packages do not protect against
quantum attacks against X25519.

The versioned package envelope and backend identifier permit future evaluation,
but backend agility is not itself a security property. Any future backend or
hybrid construction requires:

- selection of an established, reviewed implementation without inventing or
  manually composing cryptography
- explicit security goals, threat-model changes, and downgrade analysis
- a distinct reviewed backend identifier and any required format version
- canonical parsing, strict rejection behavior, limits, and metadata analysis
- compatibility and migration rules
- independent review and valid and invalid test vectors

Claims such as post-quantum security or harvest-now-decrypt-later resistance
must not be made unless they are supported by the selected construction,
implementation, tests, and independent review.

See [backend-age.md](../backend-age.md) for the current X25519 adapter and the
[roadmap](../../ROADMAP.md) for milestone ordering.
