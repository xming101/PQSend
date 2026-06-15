# Multi-file Packages

**Status:** future design note; not implemented or supported.

The current `.pqsend` format contains exactly one file and stores only one
validated filename, never a path. Folder and multi-file packages require a new
reviewed format version or mode and must not be encoded under the current
single-file format.

Any future design must define:

- canonical encrypted entry and directory representations
- deterministic, bounded traversal without following links
- duplicate, conflicting, case-folded, and platform-reserved path handling
- transactional extraction without path traversal or implicit overwrite
- resource limits and denial-of-service considerations
- public metadata leakage and authenticated inner metadata
- valid, invalid, and cross-platform test vectors

See the [roadmap](../../ROADMAP.md) for milestone ordering. This note does not
change current package framing or authorize implementation.
