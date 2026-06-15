# Release Checklist

> [!WARNING]
> PQSend is experimental and unaudited. The current backend is X25519-only and
> not post-quantum-secure. The pre-`v1.0.0` format is unstable.

Use this checklist for every PQSend release. A release is not a claim of
production readiness, post-quantum security, or external audit completion.

## Scope and security review

- [ ] Confirm the release contains only the intended milestone scope.
- [ ] Confirm no low-level cryptographic primitives or custom cryptographic
  compositions were added.
- [ ] Confirm `README.md`, `docs/FORMAT.md`, `docs/SECURITY-MODEL.md`,
  `docs/THREAT-MODEL.md`, `docs/COMPATIBILITY.md`, and CLI help match
  implemented behavior.
- [ ] Confirm public package metadata remains minimal and contains no plaintext
  filename.
- [ ] Confirm extraction rejects unsafe filenames, prevents path traversal, and
  refuses overwrite.
- [ ] Confirm security-sensitive behavior has focused tests.
- [ ] Record all unsupported features and security limitations in the release
  notes.

## Release documentation

- [ ] Add the release to `CHANGELOG.md`.
- [ ] Add standalone release notes under `docs/RELEASES/`.
- [ ] State whether the release is experimental, unaudited, post-quantum
  secure, and format-compatible with future releases.
- [ ] State the file-size limit and public metadata leakage.
- [ ] Tell users not to name the outer package after the original file when
  they want to avoid filename leakage.
- [ ] Confirm canonical format, security, threat-model, and compatibility
  documentation was updated for any behavior change.

## Validation

- [ ] Run `cargo fmt --all -- --check`.
- [ ] Run `cargo clippy --workspace --all-targets -- -D warnings`.
- [ ] Run `cargo test --workspace`.
- [ ] Review the final diff for unintended implementation or generated-file
  changes.

## Publication

- [ ] Confirm package and workspace versions match the intended release tag.
- [ ] Confirm the release tag does not already exist.
- [ ] Build release artifacts from the reviewed commit.
- [ ] Record artifact checksums.
- [ ] Create and push the signed or annotated release tag.
- [ ] Publish the release notes and artifacts.
- [ ] Verify published artifacts and links.

## `v0.1.0-alpha.1` release record

Scope reviewed for the first experimental encrypted package alpha:

- [x] age-backed X25519 adapter, fixed 20-byte public envelope, one-file
  packages, encrypted internal manifest, explicit recipient files, contacts,
  `keygen`, `pack`, `open`, safe public `inspect`, and local security receipts
  documented
- [x] format, security model, threat model, contacts, receipts, compatibility,
  and initial experimental test vectors linked from the release notes
- [x] unsupported features and security limitations documented
- [x] networking, relay/server behavior, and cloud sync explicitly documented
  as out of scope
- [x] 64 MiB v0.1 file limit documented
- [x] outer package filename leakage warning documented
- [x] pre-v1.0 format instability documented
- [x] no implementation code changed while preparing release documentation

Validation results are recorded after the required commands pass:

- [x] `cargo fmt --all -- --check`
- [x] `cargo clippy --workspace --all-targets -- -D warnings`
- [x] `cargo test --workspace`

Publication remains a separate maintainer action. The existing
`v0.1.0-alpha.1` tag points to an earlier commit that predates the documented
release scope, and the workspace package version remains `0.0.0`. Resolve
those publication/version mismatches before presenting tagged artifacts as
this documented release.
