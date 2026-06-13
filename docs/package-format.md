# Package Format Notes

The `.pqsend` format is not defined yet. `SPEC.md` contains the only current
placeholder concept, and it is deliberately non-normative.

## Design constraints

- one portable package file
- local creation and opening
- no plaintext filenames or directory names in public metadata
- minimal public metadata
- authenticated private metadata and payloads in a future design
- strict parsing, explicit resource limits, and fail-closed behavior
- safe extraction without path traversal or implicit overwrite

## Undecided

- cryptographic construction and audited implementation
- binary encoding and framing
- version identifiers and upgrade behavior
- recipient representation
- padding and size-hiding policy
- streaming and resource limits
- test-vector representation

No code should serialize or parse a `.pqsend` package until these choices have
been reviewed and reflected in `SPEC.md` and `THREAT_MODEL.md`.
