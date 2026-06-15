# Contributor and Agent Rules

These rules apply to all work in this repository.

## Security boundaries

- Do not invent cryptography.
- Do not implement low-level cryptographic primitives or manually compose them.
- Prefer existing audited or well-known backends such as `age` or `rage`.
- Do not add GUI, relay server, networking, password mode, signatures, or chat
  before the relevant milestone.
- Do not leak plaintext filenames in `.pqsend` packages.
- Do not overwrite files without explicit confirmation.
- Prevent path traversal during extraction.
- Keep public package metadata minimal.
- Do not make exaggerated or unsupported security claims.
- Add tests for security-sensitive behavior.
- Update `docs/FORMAT.md`, `docs/SECURITY-MODEL.md`, and
  `docs/THREAT-MODEL.md` whenever behavior changes.
- Keep `SPEC.md` and `THREAT_MODEL.md` compatibility pointers accurate.

## Completion checks

Run all of the following before considering work complete:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
