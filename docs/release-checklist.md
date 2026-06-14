# Release Checklist

Use this checklist for every PQSend release. A release is not a claim of
production readiness, post-quantum security, or external audit completion.

## Scope and security review

- [ ] Confirm the release contains only the intended milestone scope.
- [ ] Confirm no low-level cryptographic primitives or custom cryptographic
  compositions were added.
- [ ] Confirm `README.md`, `SPEC.md`, `THREAT_MODEL.md`, package-format
  documentation, and CLI help match implemented behavior.
- [ ] Confirm public package metadata remains minimal and contains no plaintext
  filename.
- [ ] Confirm extraction rejects unsafe filenames, prevents path traversal, and
  refuses overwrite.
- [ ] Confirm security-sensitive behavior has focused tests.
- [ ] Record all unsupported features and security limitations in the release
  notes.

## Release documentation

- [ ] Add the release to `CHANGELOG.md`.
- [ ] Add standalone release notes under `docs/releases/`.
- [ ] State whether the release is experimental, unaudited, post-quantum
  secure, and format-compatible with future releases.
- [ ] State the file-size limit and public metadata leakage.
- [ ] Tell users not to name the outer package after the original file when
  they want to avoid filename leakage.
- [ ] Confirm `SPEC.md` and `THREAT_MODEL.md` were updated for any behavior
  change.

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
  packages, encrypted internal manifest, explicit key files, `keygen`, `pack`,
  `open`, `inspect`, and local security receipts documented
- [x] unsupported features and security limitations documented
- [x] networking and Wi-Fi transfer explicitly documented as out of scope
- [x] 64 MiB v0.1 file limit documented
- [x] outer package filename leakage warning documented
- [x] pre-v1.0 format instability documented
- [x] no implementation code changed while preparing release documentation

Validation results are recorded after the required commands pass:

- [x] `cargo fmt --all -- --check`
- [x] `cargo clippy --workspace --all-targets -- -D warnings`
- [x] `cargo test --workspace`

Publication remains a separate maintainer action. In particular, confirm the
workspace version and create the `v0.1.0-alpha.1` tag only after reviewing the
release commit.
