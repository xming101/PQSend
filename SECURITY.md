# Security Policy

## Project maturity

PQSend is an experimental encrypted package format and Rust reference CLI. It
is incomplete, unaudited, X25519-only, not post-quantum-secure, and not ready
for sensitive real-world data. No security guarantees are made for it.

Pre-`v1.0.0` package formats and behaviors are unstable. Security claims must be
based on implemented, tested, and reviewed behavior rather than roadmap goals.

## Security principles

- Avoid custom cryptography and manual composition of cryptographic primitives.
- Use the high-level Rust `age` crate APIs for the experimental X25519 backend;
  do not shell out or compose low-level cryptographic primitives.
- Keep encryption and decryption local, with no telemetry or required server.
- Keep public package metadata minimal and filenames inside the encrypted
  internal manifest.
- Treat contact-key verification, private-key protection, authenticated parsing,
  path traversal prevention, and overwrite prevention as security boundaries.

PQSend has a crypto-agile architecture intended to support a future
post-quantum migration path and possible future hybrid backend. It must not
imply current post-quantum protection. See `docs/SECURITY-MODEL.md` for the
implemented design boundaries and `docs/THREAT-MODEL.md` for intended
protections and explicit limitations.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's private
security advisory feature for this repository. Include reproduction steps,
affected versions or commits, impact, and any suggested remediation.

Do not open a public issue for an undisclosed vulnerability. If private
reporting is unavailable, open a minimal issue asking maintainers for a private
contact channel without including vulnerability details.

## Security design changes

Use the security design issue template for proposals that alter trust
assumptions, package metadata, cryptographic dependencies, key handling,
receipts, or extraction behavior. Security-sensitive behavior requires tests
and matching updates to `docs/FORMAT.md`, `docs/SECURITY-MODEL.md`,
`docs/THREAT-MODEL.md`, `docs/COMPATIBILITY.md`, and the relevant design
decisions. Keep the top-level `SPEC.md` and `THREAT_MODEL.md` compatibility
pointers accurate.
