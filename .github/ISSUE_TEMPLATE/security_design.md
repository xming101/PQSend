---
name: Security design proposal
about: Propose a change to trust, package, key, or extraction behavior
title: "security design: "
labels: security-design
assignees: ""
---

Do not use this template to disclose a vulnerability. Follow `SECURITY.md`.

## Security objective

What security property or risk does this proposal address?

## Threat-model changes

Which assets, adversaries, assumptions, protections, or non-protections change?

## Proposed design

Describe behavior and boundaries. Do not invent cryptographic algorithms.

## Dependencies

Identify any proposed established libraries or formats and their review status.

## Metadata and privacy

What becomes public, private, observable, or linkable?

## Failure behavior

How does the design fail closed on malformed input, unavailable resources, or
unexpected state?

## Test plan

List security-sensitive tests and test vectors.

## Documentation updates

Describe required changes to `docs/FORMAT.md`, `docs/SECURITY-MODEL.md`,
`docs/THREAT-MODEL.md`, `docs/COMPATIBILITY.md`, and design docs.
