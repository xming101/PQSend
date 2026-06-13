# Security Policy

## Project maturity

PQSend is experimental and does not implement encryption yet. Do not use it for
sensitive real-world data.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's private
security advisory feature for this repository. Include reproduction steps,
affected versions or commits, impact, and any suggested remediation.

Do not open a public issue for an undisclosed vulnerability. If private
reporting is unavailable, open a minimal issue asking maintainers for a private
contact channel without including vulnerability details.

## Security design changes

Use the security design issue template for proposals that alter trust
assumptions, package metadata, cryptographic dependencies, key handling, or
extraction behavior. Security-sensitive behavior requires tests and matching
updates to `SPEC.md` and `THREAT_MODEL.md`.

No security guarantees are made for the current repository skeleton.
