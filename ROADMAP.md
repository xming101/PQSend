# Roadmap

PQSend is being developed in small, reviewable milestones. Milestone boundaries
are security boundaries: features listed later should not be pulled forward
without an explicit design review.

## Milestone 0: Repository skeleton

- Rust workspace and stub CLI
- initial threat model and placeholder specification
- CI, issue templates, and contributor guidance
- no encryption or package handling

## Milestone 1: Local identities and contacts

- select well-known libraries and a key representation after review
- local identity initialization
- contact import, listing, fingerprint display, and explicit verification state
- tests for filesystem permissions, parsing, and trust-state transitions

## Milestone 2: First experimental package format

- select an established encryption construction and implementation
- encrypt file contents and private manifest locally
- hide plaintext filenames
- minimal public metadata
- safe extraction with path-traversal and overwrite protections
- publish test vectors

The format remains experimental until it has received independent review.

## Milestone 3: Hardening

- malformed-package and fuzz testing
- resource-limit protections
- compatibility and migration policy
- external security review

## Deferred

Post-quantum cryptography, signatures, password mode, GUI, networking, relay
services, and chat are intentionally outside the early milestones. Each needs a
separate threat-model and design update before implementation.
