# Reference GUI

**Status:** future design note; no GUI is implemented or supported.

PQSend is currently an experimental package format with a Rust reference CLI.
A future reference GUI would be an interface over reviewed core behavior, not a
new package format, messaging app, cloud sending service, or required relay.

Any future GUI design must preserve:

- local package creation and opening
- explicit recipient selection and verification meaning
- minimal public package metadata
- safe extraction, path traversal prevention, and overwrite refusal
- clear display of X25519-only, unaudited, pre-v1 status
- accurate receipt meaning without implying signatures, identity, or delivery
  proof
- no networking, telemetry, or server dependency unless separately designed
  and reviewed in a later milestone

See the [roadmap](../../ROADMAP.md) for milestone ordering. This note does not
authorize GUI implementation.
