# Package Format Notes

`SPEC.md` defines the current draft `.pqsend` `v0.1` package concept. The format
is experimental and unstable before `v1.0.0`; these notes explain the design
rationale and remaining choices without defining a separate format.

## `v0.1` boundary

- one portable package file
- one encrypted input file
- one recipient
- local creation and opening
- no telemetry or required server
- no folders, multiple recipients, signatures, password mode, GUI, relay, or
  chat

## Privacy boundary

The public envelope may identify the format, format version, implementation
version, package mode, backend, and encrypted payload location. It must not
contain a plaintext filename, folder path, note, message, or recipient display
name by default.

The authenticated encrypted payload contains the internal manifest and file
body. The manifest carries the original filename, file size, file hash, an
optional justified creation timestamp, and a reserved future note field.

Backend-required public recipient material, approximate package size, transfer
timing, and transport metadata cannot necessarily be hidden.

## Backend boundary

The package layer delegates encryption to an existing, well-known backend such
as `age` or `rage`; it does not define custom cryptography. A backend identifier
allows future migration, but migration behavior and downgrade handling must be
specified before multiple backends are supported.

## Parser and extraction boundary

- authenticate encrypted data before trusting the manifest or writing output
- use strict parsing, explicit resource limits, and fail-closed behavior
- treat the decrypted filename as untrusted and reject path-like values
- prevent path traversal and platform-specific path confusion
- never overwrite an existing file without explicit confirmation

## Undecided

- concrete backend and backend identifier registry
- binary encoding and framing
- implementation-version inclusion policy
- recipient-material representation and metadata impact
- file-hash algorithm and receipt presentation
- padding and size-hiding policy
- streaming and resource limits
- test-vector representation

No code should serialize or parse a `.pqsend` package until these choices have
been reviewed and reflected in `SPEC.md` and `THREAT_MODEL.md`.
