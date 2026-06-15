# PQSend Documentation

PQSend is an experimental encrypted package format and Rust reference CLI for
private file delivery. The current implementation and format are unaudited,
X25519-only, not post-quantum-secure, and unstable before `v1.0.0`.

This directory is the documentation home for the format, security boundaries,
compatibility rules, design record, and release records.

## Start here

Read the current project documentation in this order:

1. [Package format](FORMAT.md) - canonical implementer-facing `.pqsend` wire
   format and parsing rules
2. [Security model](SECURITY-MODEL.md) - implemented trust and security
   boundaries
3. [Threat model](THREAT-MODEL.md) - scoped protections, assumptions, and
   explicit non-protections
4. [Contacts](CONTACTS.md) - local recipient trust-store model
5. [Security receipts](RECEIPTS.md) - local receipt meaning and limitations
6. [Compatibility](COMPATIBILITY.md) - current reader, writer, store, and
   versioning rules
7. [Test vectors](../test-vectors/README.md) - publication layout and vector
   status
8. [Roadmap](../ROADMAP.md) - milestone boundaries and deferred work
9. [Changelog](../CHANGELOG.md) - release-level changes

## Supporting documentation

- [Design decisions](design-decisions.md) records cross-cutting decisions that
  shape the current project.
- [Current age backend note](backend-age.md) documents the narrow Rust `age`
  X25519 adapter used by the reference implementation.
- [Future design notes](DESIGNS/README.md) collect non-current proposals and
  review questions. They are not specifications or implemented features.
- [Release records](RELEASES/README.md) contain release notes and the release
  checklist.
- [Backlog](backlog.md) is a planning record, not a source of current format or
  security behavior.
- The top-level [security policy](../SECURITY.md) explains private
  vulnerability reporting and security-change expectations.

## Sources of truth

- `FORMAT.md` is the only wire-format specification.
- `SECURITY-MODEL.md` and `THREAT-MODEL.md` define current security scope.
- `CONTACTS.md` and `RECEIPTS.md` define their respective local models.
- `COMPATIBILITY.md` defines current compatibility policy.
- The Rust crates are the reference implementation, but their behavior does
  not override the documented format.

The top-level [`SPEC.md`](../SPEC.md), top-level
[`THREAT_MODEL.md`](../THREAT_MODEL.md), and
[`package-format.md`](package-format.md) are retained compatibility pointers.
Do not develop competing specifications in those files.
