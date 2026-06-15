# Roadmap

PQSend is being developed in small, reviewable milestones. Milestone boundaries
are security boundaries: later features must not be pulled forward without an
explicit design review and matching updates to the canonical
[format](docs/FORMAT.md), [security model](docs/SECURITY-MODEL.md), and
[threat model](docs/THREAT-MODEL.md).

All pre-`v1.0.0` formats and behaviors are experimental and may change without
backward compatibility.

The current implementation is experimental, unaudited, X25519-only, and not
post-quantum-secure. Roadmap items are not current capabilities or security
claims.

## Current alpha: v0.1.0-alpha.1

The first experimental encrypted package alpha includes:

- canonical `.pqsend` package-format, security-model, threat-model, receipt,
  contact, and compatibility documentation
- Rust reference CLI
- one-file package creation and authenticated opening for exactly one
  recipient
- fixed public envelope and encrypted internal manifest with hidden original
  filename
- age-backed X25519 backend and explicit recipient-file workflow
- local contact selection with recipient-bound verification
- safe public inspection and local human-readable security receipts
- initial experimental `v0-alpha` test vectors and security-sensitive tests

This alpha does not include a stable package format, post-quantum security,
folders or multiple files, multiple recipients, signatures, password mode,
GUI, networking, relay/server behavior, cloud sync, messaging, or chat.

## Next: Format and parser hardening

- malformed-package, resource-limit, and fuzz testing
- compatibility and migration-policy hardening
- broader cross-platform package test vectors
- independent review of the package and extraction design

## Later roadmap: Folder and multi-file packages

- reviewed [multi-file and folder package design](docs/DESIGNS/multi-file-packages.md)
- encrypted folder structure and filenames
- safe extraction of directory trees
- duplicate, conflicting, and platform-specific path handling

## Later roadmap: Multiple recipients

- packages addressed to multiple independently selected recipients
- clear receipt and inspection behavior for recipient sets
- metadata and privacy review for backend recipient material

## Later roadmap: Optional authenticity and password features

- evaluate signatures only after defining their user meaning and failure modes
- evaluate password mode only after a separate threat-model update
- keep both features optional and distinct from recipient encryption

## Later roadmap: Optional graphical interface

- follow the reviewed
  [reference GUI design](docs/DESIGNS/reference-gui.md)
- local-first GUI built on the reviewed core package and contact behavior
- preserve the existing `.pqsend` format and security model
- preserve safe defaults and explicit confirmation for destructive actions
- no account system, cloud sync, required server, or telemetry

## Later roadmap: Backend agility and post-quantum evaluation

- follow the reviewed
  [backend-agility and future hybrid PQC design](docs/DESIGNS/backend-agility-and-pqc.md)
- document and test backend migration behavior
- evaluate a reviewed hybrid future-resistant backend
- claim harvest-now-decrypt-later resistance only if supported by the selected
  construction and independent review

## Later roadmap: Release candidate

- stabilize the candidate format and user workflows
- complete external security review and remediate findings
- publish compatibility, recovery, and operational guidance

## Later roadmap: v1.0.0 stable package layer

- stable `.pqsend` format and compatibility commitment
- documented security properties and limitations
- production-readiness decision based on implementation and external review

An optional relay service may be considered after local package workflows are
mature, but PQSend will not require a server and any server must be unable to
decrypt file contents. Chat is not planned before `v1.0.0`.

Future-facing design notes are indexed in
[`docs/DESIGNS/`](docs/DESIGNS/README.md). They describe review questions, not
implemented features or commitments.
