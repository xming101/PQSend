# Design Decisions

This log records decisions that shape multiple parts of PQSend. It is not a
substitute for `SPEC.md` or `THREAT_MODEL.md`.

## DD-001: Local-first portable packages

PQSend creates files that can be transported by unrelated tools. It does not
require or provide a network service. Sensitive operations are intended to
happen locally.

## DD-002: Established cryptography only

PQSend will not invent cryptographic algorithms or manually implement low-level
cryptography. Algorithm and library selection is deferred until a reviewed
milestone with explicit threat-model and specification updates.

## DD-003: Private filenames and minimal metadata

Plaintext filenames belong in a future authenticated private manifest, not in
public package metadata. Public metadata should contain only what is necessary
to parse and open a package.

## DD-004: Safe extraction is part of the security boundary

Extraction must prevent path traversal and must not overwrite existing files
without explicit confirmation. These behaviors require security-sensitive
tests before package opening is implemented.

## DD-005: No stable v0 format

The placeholder v0 concept exists to support design discussion. It carries no
compatibility promise and does not select an encoding or cryptographic
construction.
