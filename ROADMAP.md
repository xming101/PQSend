# Roadmap

PQSend is being developed in small, reviewable milestones. Milestone boundaries
are security boundaries: later features must not be pulled forward without an
explicit design review and matching updates to the canonical
[format](docs/FORMAT.md), [security model](docs/SECURITY-MODEL.md), and
[threat model](docs/THREAT-MODEL.md).

All pre-`v1.0.0` formats and behaviors are experimental and may change without
backward compatibility.

The current implementation is an unaudited, X25519-only Rust reference CLI and
is not post-quantum-secure. Roadmap items are not current capabilities or
security claims.

## v0.0.1: Repository skeleton

- Rust workspace and stub CLI
- initial threat model, draft specification, CI, and contributor guidance
- no encryption or package handling

## v0.1.0: One file, one recipient

- select and integrate a reviewed existing backend such as `age` or `rage`
- create and open one `.pqsend` package containing one file for one recipient
- accept one explicitly supplied recipient public key
- encrypt the file contents and internal manifest, including the filename
- expose only the minimal public metadata defined by the draft specification
- prevent path traversal and implicit overwrite during extraction
- print local security receipts for successful package creation and opening
- add package test vectors and security-sensitive tests

Folder support, multiple recipients, signatures, password mode, GUI, relay
server, and chat are explicitly out of scope for `v0.1`.

## v0.2.0: Contacts and verification

- hardened experimental contact store, X25519 parsing, fingerprints, and
  verification binding
- CLI-only `pack --to <contact>` integration preserving the package boundary
- local identity workflows
- contact fingerprint display and recipient-bound verification status
- integrate and extend local security receipts for contact-based workflows
- tests for filesystem permissions, parsing, and trust-state transitions

## v0.3.0: Format and parser hardening

- malformed-package, resource-limit, and fuzz testing
- documented compatibility and migration policy
- broader cross-platform package test vectors
- independent review of the package and extraction design

## v0.4.0: Folder packages

- reviewed [multi-file and folder package design](docs/DESIGNS/multi-file-packages.md)
- encrypted folder structure and filenames
- safe extraction of directory trees
- duplicate, conflicting, and platform-specific path handling

## v0.5.0: Multiple recipients

- packages addressed to multiple independently selected recipients
- clear receipt and inspection behavior for recipient sets
- metadata and privacy review for backend recipient material

## v0.6.0: Optional authenticity features

- evaluate signatures only after defining their user meaning and failure modes
- evaluate password mode only after a separate threat-model update
- keep both features optional and distinct from recipient encryption

## v0.7.0: Optional graphical interface

- GUI built on the reviewed core package and contact behavior
- preserve safe defaults and explicit confirmation for destructive actions
- no required server and no telemetry

## v0.8.0: Backend agility and future-resistant evaluation

- document and test backend migration behavior
- evaluate a reviewed hybrid future-resistant backend
- claim harvest-now-decrypt-later resistance only if supported by the selected
  construction and independent review

## v0.9.0: Release candidate

- stabilize the candidate format and user workflows
- complete external security review and remediate findings
- publish compatibility, recovery, and operational guidance

## v1.0.0: Stable package layer

- stable `.pqsend` format and compatibility commitment
- documented security properties and limitations
- production-readiness decision based on implementation and external review

An optional relay service may be considered after local package workflows are
mature, but PQSend will not require a server and any server must be unable to
decrypt file contents. Chat is not planned before `v1.0.0`.

Future-facing design notes are indexed in
[`docs/DESIGNS/`](docs/DESIGNS/README.md). They describe review questions, not
implemented features or commitments.
