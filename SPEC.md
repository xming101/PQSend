# PQSend Placeholder Specification

## Status

This document describes a placeholder `v0` package concept only. It is
non-normative, incomplete, and intentionally does not define a stable or
interoperable format. Implementations must not treat it as a production
specification.

No encryption or package serialization is implemented in the repository.

## Goals

A future `.pqsend` package should:

- be a portable single-file container
- be created and opened locally
- protect file contents and plaintext filenames
- expose as little public metadata as practical
- detect modification before extraction
- extract without path traversal or implicit overwrite

## Placeholder v0 concept

Conceptually, a future package may contain:

1. a small public envelope needed to identify and parse an experimental format
2. recipient-related material required by a selected, reviewed construction
3. an authenticated private manifest containing filenames and file metadata
4. authenticated encrypted file payloads

The exact byte layout, encoding, algorithms, identifiers, limits, and versioning
rules are deliberately unspecified. No algorithm choice is implied by this
concept.

## Public metadata

Public metadata must remain minimal. Plaintext filenames, directory names,
comments, sender labels, recipient contact names, and user-supplied descriptions
must not appear in the public package metadata.

Some information, such as total package size and transport-level metadata,
cannot be hidden by the package format.

## Extraction requirements

A future opener must authenticate package data before trusting private metadata
or writing output. It must reject absolute paths, parent-directory traversal,
unsafe platform path forms, duplicate/conflicting output paths, and resource
limits exceeded by the package. It must not overwrite existing files without
explicit confirmation.

## Compatibility

There is no compatibility promise for placeholder `v0`. Any experimental
implementation must clearly identify its format revision and fail closed on
unknown or malformed input.

## Change policy

Any implementation-level format proposal requires updates to this document,
`THREAT_MODEL.md`, design rationale, test vectors, and security-sensitive tests
before it can be considered complete.
