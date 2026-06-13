# PQSend Backlog

This backlog breaks the first PQSend milestones into GitHub issue-style tasks.
Issues within a milestone are roughly dependency ordered. Every behavior change
must include the corresponding `SPEC.md` and `THREAT_MODEL.md` updates before it
is complete.

Pre-`v1.0.0` package formats are experimental and carry no compatibility
promise. Work must use an established encryption backend rather than inventing
or manually composing cryptographic primitives.

## v0.0.1 Skeleton

### Issue: Establish the Rust workspace and crate boundaries

**Purpose**

Create a minimal workspace that separates reusable package behavior from the
command-line interface.

**Acceptance criteria**

- [ ] The workspace contains `pqsend-core` and `pqsend-cli` crates.
- [ ] Both crates build on the documented stable Rust toolchain.
- [ ] The core crate contains no CLI-specific behavior.
- [ ] The workspace passes formatting, linting, and test checks.

**Out of scope**

- Encryption, package serialization, extraction, and production CLI behavior.

### Issue: Add non-destructive CLI command stubs

**Purpose**

Document the intended command shape without implying that security-sensitive
operations are implemented.

**Acceptance criteria**

- [ ] Stub commands parse the intended arguments and clearly report that they
  are not implemented.
- [ ] Stub commands do not read, create, overwrite, encrypt, or decrypt user
  files.
- [ ] Help text labels the project as experimental.

**Out of scope**

- Functional package, contact, identity, or receipt commands.

### Issue: Document the initial specification and threat model

**Purpose**

Define the narrow product and security boundaries that future implementation
issues must follow.

**Acceptance criteria**

- [ ] `SPEC.md` defines the draft single-file, single-recipient package concept.
- [ ] `THREAT_MODEL.md` states assets, assumptions, protections, limitations,
  and required review triggers.
- [ ] Documentation explicitly rejects custom cryptography and unsupported
  security claims.
- [ ] Deferred features are listed clearly.

**Out of scope**

- Claims that PQSend is production-ready or post-quantum secure.

### Issue: Enforce repository completion checks in CI

**Purpose**

Make baseline quality checks repeatable before security-sensitive behavior is
introduced.

**Acceptance criteria**

- [ ] CI runs `cargo fmt --all -- --check`.
- [ ] CI runs `cargo clippy --workspace --all-targets -- -D warnings`.
- [ ] CI runs `cargo test --workspace`.
- [ ] Contributor guidance lists the same required checks.

**Out of scope**

- Release publishing, artifact signing, and deployment automation.

## v0.1.0 Single-file package

### Issue: Select and document the v0.1 encryption backend

**Purpose**

Choose a well-known, maintained backend that provides recipient encryption and
authenticated payload protection without custom cryptographic composition.

**Acceptance criteria**

- [ ] The backend, supported key type, exact dependency, and minimum supported
  version are documented.
- [ ] The review records maintenance status, license, security history, and
  upstream interoperability expectations.
- [ ] Backend-required public recipient material and its metadata impact are
  documented.
- [ ] `SPEC.md`, `THREAT_MODEL.md`, and the design-decision log reflect the
  selection before package code is merged.

**Out of scope**

- Multiple backends, backend migration, password encryption, signatures, and
  claims of post-quantum protection.

### Issue: Finalize the draft v0.1 package framing

**Purpose**

Define an unambiguous, strictly parseable container before implementing package
serialization.

**Acceptance criteria**

- [ ] The format specifies magic bytes, version dispatch, single-file mode,
  backend identifier, payload framing, and end-of-package handling.
- [ ] Every public field has a documented size limit and canonical encoding.
- [ ] Unknown versions, modes, backends, fields, and trailing data have explicit
  fail-closed behavior.
- [ ] The public envelope contains no plaintext filename, source path, note,
  recipient display name, or user-supplied description.

**Out of scope**

- A stable compatibility promise, folders, multiple recipients, and optional
  extension fields.

### Issue: Define the encrypted internal manifest schema

**Purpose**

Specify the authenticated metadata needed to safely validate and restore one
file.

**Acceptance criteria**

- [ ] The manifest contains a filename only, file size, and a hash produced by
  a documented well-known implementation.
- [ ] The manifest encoding is canonical and has explicit field and total-size
  limits.
- [ ] Source directory paths and timestamps are excluded unless separately
  justified and reviewed.
- [ ] Malformed, duplicate, missing, and unknown fields have documented
  rejection behavior.

**Out of scope**

- Folder entries, notes, messages, receipts, and user-defined metadata.

### Issue: Define package and extraction resource limits

**Purpose**

Prevent malformed or hostile packages from causing unbounded allocation, disk
use, or parsing work.

**Acceptance criteria**

- [ ] Limits exist for public envelope size, encrypted payload size, manifest
  size, filename length, and extracted file size.
- [ ] Limits are enforced before allocation or output-file creation whenever
  possible.
- [ ] Boundary, overflow, truncation, and excessive-size cases have tests.
- [ ] Limit choices and denial-of-service limitations are documented.

**Out of scope**

- Guarantees against all denial-of-service attacks and configurable enterprise
  policy.

### Issue: Add a narrow backend adapter in pqsend-core

**Purpose**

Keep package logic independent from backend-specific APIs while exposing only
the operations required by the single-recipient milestone.

**Acceptance criteria**

- [ ] The adapter supports encrypting for exactly one explicitly supplied
  recipient public key and decrypting with local recipient key material.
- [ ] Backend authentication failures remain distinguishable from valid
  packages without leaking plaintext details.
- [ ] Private key material is never logged or serialized into a package.
- [ ] Tests exercise successful round trips and backend failure propagation.

**Out of scope**

- Implementing primitives, multiple recipients, contacts, signatures, password
  mode, and backend agility.

### Issue: Implement strict public-envelope serialization and parsing

**Purpose**

Create and parse only the reviewed v0.1 public metadata with deterministic,
fail-closed behavior.

**Acceptance criteria**

- [ ] Serialization emits only the fields allowed by the v0.1 specification.
- [ ] Parsing rejects malformed framing, unsupported identifiers, invalid
  encodings, truncation, and disallowed trailing data.
- [ ] Parsing enforces all public-envelope limits before processing encrypted
  payload bytes.
- [ ] Tests confirm that plaintext filenames and recipient display names never
  appear in serialized packages.

**Out of scope**

- Decryption, extraction, permissive parsing, and recovery of malformed
  packages.

### Issue: Implement single-file package creation

**Purpose**

Create one portable `.pqsend` package that protects one regular file and its
filename for one recipient.

**Acceptance criteria**

- [ ] Creation accepts exactly one regular input file and one explicit
  recipient public key.
- [ ] The filename and manifest are inside the authenticated encrypted payload.
- [ ] Directories, symlinks, special files, and files exceeding documented
  limits are rejected.
- [ ] A failed operation does not leave a package that appears complete.
- [ ] The destination package is not overwritten without explicit
  confirmation.

**Out of scope**

- Contacts, folders, multiple input files, multiple recipients, notes,
  signatures, password mode, and transport.

### Issue: Authenticate and validate packages before extraction

**Purpose**

Ensure untrusted package data is not trusted or written before backend
authentication and manifest validation succeed.

**Acceptance criteria**

- [ ] The complete authenticated payload is verified before an extracted output
  file becomes visible at its final path.
- [ ] Manifest size and hash agree with the authenticated file body before
  success is reported.
- [ ] Authentication, truncation, corruption, and manifest-validation failures
  create no final output file.
- [ ] Failure messages do not reveal decrypted filenames or contents by
  default.

**Out of scope**

- Repairing corrupt packages and unauthenticated partial extraction.

### Issue: Enforce safe single-filename extraction

**Purpose**

Treat the decrypted filename as hostile input and keep extraction inside the
user-selected output directory.

**Acceptance criteria**

- [ ] Absolute paths, parent traversal, separators, empty names, dot names,
  unsafe platform names, and platform-specific path ambiguities are rejected.
- [ ] Extraction creates only a direct child file of the selected output
  directory.
- [ ] Security-sensitive tests cover Unix, Windows, and mixed-separator attack
  forms.
- [ ] `SPEC.md` and `THREAT_MODEL.md` document the implemented filename policy.

**Out of scope**

- Directory trees, filename normalization for convenience, and automatic
  renaming.

### Issue: Prevent implicit overwrite and partial-output exposure

**Purpose**

Protect existing destination files and avoid presenting incomplete plaintext as
a successful extraction.

**Acceptance criteria**

- [ ] Existing files are never overwritten without explicit confirmation.
- [ ] The implementation handles races between conflict checks and final file
  placement without silently replacing a file.
- [ ] Failed extraction cleans up temporary plaintext output where possible and
  documents residual filesystem limitations.
- [ ] Tests cover conflicts, interrupted writes, and failed final placement.

**Out of scope**

- Secure deletion guarantees and unattended overwrite policies.

### Issue: Add the v0.1 pack CLI using explicit recipient keys

**Purpose**

Expose single-file package creation without pulling the contact workflow into
the first package milestone.

**Acceptance criteria**

- [ ] The command requires one input file, one explicit recipient public-key
  source, and an explicit or predictably derived output package path.
- [ ] The command rejects ambiguous inputs and requests confirmation before any
  overwrite.
- [ ] Success output avoids plaintext filenames and sensitive paths unless
  necessary for the immediate local operation.
- [ ] Help text states the single-file, single-recipient, experimental limits.

**Out of scope**

- Contact names, key discovery, multiple recipients, networking, and GUI.

### Issue: Add the v0.1 open CLI with explicit destination control

**Purpose**

Expose authenticated package opening while keeping extraction location and
overwrite decisions visible to the user.

**Acceptance criteria**

- [ ] The command requires a package and an explicit output directory.
- [ ] The command fails closed on unsupported or malformed packages.
- [ ] Overwrite confirmation identifies the conflict without logging unrelated
  decrypted metadata.
- [ ] Exit status distinguishes success from rejection or failure without
  exposing secrets.

**Out of scope**

- Contact lookup, automatic opening, previewing plaintext, and GUI prompts.

### Issue: Add privacy-preserving public package inspection

**Purpose**

Allow users and tests to inspect the public envelope without decrypting or
misrepresenting what the package proves.

**Acceptance criteria**

- [ ] Inspection displays only documented public-envelope fields and package
  size information.
- [ ] Inspection never attempts extraction or displays decrypted filenames,
  contents, contact names, or private key material.
- [ ] Output clearly states that inspection does not prove authorship,
  delivery, or payload safety.
- [ ] Malformed and unsupported packages fail closed.

**Out of scope**

- Security receipts, signature verification, and encrypted-manifest preview.

### Issue: Define redacted errors and operational logging

**Purpose**

Make failures useful without leaking plaintext metadata, key material, or
unnecessary filesystem details.

**Acceptance criteria**

- [ ] Error categories and user-facing messages are documented for pack, open,
  parse, authentication, limit, and extraction failures.
- [ ] Default errors and logs contain no private key material, file contents, or
  decrypted filename.
- [ ] Tests cover representative redaction-sensitive failures.
- [ ] Debug behavior and its privacy implications are documented.

**Out of scope**

- Telemetry, remote logging, analytics, and exported security receipts.

### Issue: Publish v0.1 package test vectors

**Purpose**

Make package behavior reproducible and detect accidental format or backend
compatibility changes.

**Acceptance criteria**

- [ ] Vectors include a successful package, public-envelope expectations, and
  deterministic fixtures where the selected backend permits them safely.
- [ ] Negative vectors cover tampering, truncation, unsupported identifiers,
  malformed framing, and invalid manifests.
- [ ] Vector generation and verification procedures are documented.
- [ ] Fixtures contain no real identities, private production keys, or
  sensitive data.

**Out of scope**

- A permanent pre-v1 compatibility promise and vectors for deferred features.

### Issue: Add adversarial v0.1 security tests

**Purpose**

Verify the security-sensitive boundaries of package creation, parsing,
authentication, and extraction.

**Acceptance criteria**

- [ ] Tests cover metadata leakage, authentication failure, path traversal,
  overwrite refusal, symlink and special-file rejection, resource limits, and
  cleanup after failure.
- [ ] Tests assert that rejected inputs create no final plaintext output.
- [ ] Tests include platform-specific cases supported by CI.
- [ ] Every fixed security regression receives a focused regression test.

**Out of scope**

- Formal verification and guarantees against compromised dependencies or
  operating systems.

### Issue: Complete the v0.1 security and documentation review

**Purpose**

Confirm that the implemented milestone matches its narrow claims before it is
released.

**Acceptance criteria**

- [ ] `SPEC.md`, `THREAT_MODEL.md`, package-format notes, and CLI help match
  implemented behavior.
- [ ] Dependency review and test-vector results are recorded.
- [ ] Formatting, linting, workspace tests, and security-sensitive tests pass.
- [ ] Release notes state that the format is experimental and not ready for
  sensitive real-world data.

**Out of scope**

- Production-readiness claims, external audit completion, and stable-format
  guarantees.

## v0.2.0 Contact UX

### Issue: Define local identity and contact storage

**Purpose**

Specify how local keys and contact public keys are stored without weakening
filesystem or metadata protections.

**Acceptance criteria**

- [ ] Storage locations, file formats, permissions, backup expectations, and
  failure behavior are documented.
- [ ] Private and public material have separate handling rules.
- [ ] Contact records contain only necessary local metadata.
- [ ] `SPEC.md` and `THREAT_MODEL.md` cover identity and contact trust.

**Out of scope**

- Cloud sync, key servers, automatic discovery, account systems, and hardware
  key support.

### Issue: Add explicit contact import and replacement safety

**Purpose**

Let users add contact public keys while making key substitution and accidental
replacement visible.

**Acceptance criteria**

- [ ] Import validates the selected backend's public-key format.
- [ ] Adding an existing contact name or key requires explicit confirmation.
- [ ] Replacing a key resets verification status and clearly shows the
  fingerprint change.
- [ ] Malformed records and unsafe local permissions fail closed.

**Out of scope**

- Remote lookup, trust-on-first-use claims, and automatic verification.

### Issue: Add contact fingerprints and verification states

**Purpose**

Help users compare contact keys through an independent trusted channel without
claiming that PQSend performed identity verification.

**Acceptance criteria**

- [ ] Fingerprints use the selected backend's documented representation or
  another reviewed standard representation.
- [ ] Contacts have explicit unverified and verified states.
- [ ] Verification requires a deliberate local action and records only minimal
  necessary metadata.
- [ ] Trust-state transitions and key replacement have security-sensitive
  tests.

**Out of scope**

- Web-of-trust, certificate authorities, automated identity proof, and
  signatures.

### Issue: Integrate contacts into recipient selection

**Purpose**

Allow single-recipient package creation by local contact name while preserving
clear key and verification-state visibility.

**Acceptance criteria**

- [ ] Pack resolves exactly one contact to exactly one public key.
- [ ] Recipient selection displays verification status before confirmation.
- [ ] Missing, ambiguous, malformed, or changed contacts fail closed.
- [ ] Packages still exclude plaintext contact display names by default.

**Out of scope**

- Multiple recipients, remote contacts, and silent recipient selection.

### Issue: Add local, privacy-preserving security receipts

**Purpose**

Record human-readable summaries of local choices and completed checks without
presenting them as signatures or delivery proofs.

**Acceptance criteria**

- [ ] Receipt purpose, storage, retention, redaction, and trust limits are
  documented before implementation.
- [ ] Receipts remain local and are never embedded in the public package
  envelope.
- [ ] Default receipts omit plaintext filenames, paths, contents, and private
  key material.
- [ ] Receipt tests cover redaction and accurate verification-state reporting.

**Out of scope**

- Signatures, proof of authorship, proof of delivery, remote receipt exchange,
  and telemetry.

## v0.3.0 Folder support

### Issue: Specify the encrypted folder manifest

**Purpose**

Extend the authenticated internal manifest to represent a directory tree while
keeping all names and structure encrypted.

**Acceptance criteria**

- [ ] The specification defines canonical relative paths, entry types,
  ordering, duplicate handling, and total limits.
- [ ] Public metadata reveals neither folder names nor structure.
- [ ] Symlinks, hard links, devices, sockets, and other special entries have
  explicit rejection behavior.
- [ ] `SPEC.md` and `THREAT_MODEL.md` are updated before implementation.

**Out of scope**

- Filesystem metadata preservation, permissions cloning, links, sparse-file
  guarantees, and multiple recipients.

### Issue: Implement deterministic and bounded folder walking

**Purpose**

Collect eligible folder entries without following links or exceeding reviewed
resource limits.

**Acceptance criteria**

- [ ] Walking never follows symlinks and rejects unsupported entry types.
- [ ] Entry count, depth, individual file size, and total plaintext size limits
  are enforced.
- [ ] Ordering is deterministic for the documented path representation.
- [ ] Filesystem races and changed inputs produce a clear failure rather than a
  misleading success.

**Out of scope**

- Live snapshots, filesystem watchers, and backup-tool semantics.

### Issue: Implement encrypted folder package creation

**Purpose**

Create one package containing a bounded directory tree for one selected
contact.

**Acceptance criteria**

- [ ] All relative paths, filenames, and file bodies are inside the
  authenticated encrypted payload.
- [ ] Folder packages have an explicit version or mode and cannot be confused
  with single-file packages.
- [ ] Failed creation leaves no package that appears complete.
- [ ] Metadata-leakage and resource-limit tests cover folder packages.

**Out of scope**

- Multiple recipients, incremental updates, deduplication, and compression
  unless separately reviewed.

### Issue: Implement transactional safe folder extraction

**Purpose**

Extract a directory tree without traversal, collisions, implicit overwrite, or
partially visible success.

**Acceptance criteria**

- [ ] Every path is validated before final placement begins.
- [ ] Absolute paths, traversal, duplicate paths, case-folding collisions,
  Unicode-normalization collisions, and file-directory conflicts are rejected.
- [ ] Existing destination entries are never overwritten without explicit
  confirmation.
- [ ] Failure behavior and unavoidable filesystem atomicity limits are
  documented and tested.

**Out of scope**

- Merging into arbitrary existing trees and secure deletion guarantees.

### Issue: Add cross-platform folder-package test vectors

**Purpose**

Validate consistent path and extraction behavior across supported platforms.

**Acceptance criteria**

- [ ] Vectors cover nested trees, empty directories if supported, mixed path
  forms, collisions, and platform-reserved names.
- [ ] Tests confirm that rejected trees create no final extracted tree.
- [ ] Supported-platform differences are documented explicitly.
- [ ] Independent parser and extraction review findings are resolved or
  documented before release.

**Out of scope**

- Compatibility guarantees for unsupported filesystems and operating systems.

## v0.4.0 Multiple recipients

### Issue: Specify recipient-set package semantics

**Purpose**

Define how one encrypted payload can be opened by multiple independently
selected recipients without ambiguous selection or unsupported privacy claims.

**Acceptance criteria**

- [ ] The specification defines recipient ordering, duplicates, maximum count,
  backend material, and failure behavior.
- [ ] Public metadata exposure from recipient material is analyzed and
  documented.
- [ ] Downgrade and recipient-removal risks are considered.
- [ ] `SPEC.md` and `THREAT_MODEL.md` are updated before implementation.

**Out of scope**

- Group accounts, dynamic membership, revocation of already-created packages,
  and hidden-recipient guarantees unless the backend provides and documents
  them.

### Issue: Add explicit multi-recipient selection UX

**Purpose**

Make the exact recipient set and each contact's verification state visible
before package creation.

**Acceptance criteria**

- [ ] Users deliberately select each recipient and confirm the final set.
- [ ] Duplicate, missing, malformed, changed, or ambiguous contacts fail
  closed.
- [ ] Unverified recipients are clearly identified without claiming they are
  unsafe or verified.
- [ ] Confirmation and error output avoid leaking the recipient set into the
  package or unrelated logs.

**Out of scope**

- Automatic groups, remote directories, and policy-managed recipient sets.

### Issue: Implement bounded multi-recipient package creation and opening

**Purpose**

Allow each selected recipient to open the same authenticated payload through
the reviewed backend's supported mechanism.

**Acceptance criteria**

- [ ] Package creation enforces the documented recipient-count limit.
- [ ] Recipient handling uses backend-supported APIs without custom
  cryptographic composition.
- [ ] Any intended recipient can open the package, and unrelated keys cannot.
- [ ] Single-recipient package handling remains covered by regression tests.

**Out of scope**

- Recipient revocation after creation, threshold decryption, and signatures.

### Issue: Extend receipts and tests for recipient sets

**Purpose**

Accurately represent local multi-recipient choices and test metadata and
authorization boundaries.

**Acceptance criteria**

- [ ] Local receipts describe the selected recipient set and verification
  states without entering the package envelope.
- [ ] Tests cover duplicate recipients, maximum counts, wrong keys, tampering,
  recipient-order behavior, and metadata leakage.
- [ ] Documentation states that encryption does not prove which recipient
  opened or received a package.
- [ ] Security review addresses backend recipient-material privacy.

**Out of scope**

- Delivery tracking, read receipts, proof of receipt, and recipient anonymity
  claims.

## v1.0.0 Stable format

### Issue: Define the stable compatibility and evolution policy

**Purpose**

Turn the reviewed package format into an explicit compatibility commitment with
fail-closed extension rules.

**Acceptance criteria**

- [ ] Supported stable versions, modes, backends, and extension behavior are
  documented.
- [ ] Reader and writer compatibility expectations are testable and
  unambiguous.
- [ ] Unknown critical data fails closed, and downgrade behavior is specified.
- [ ] Migration and deprecation rules do not require silent format rewriting.

**Out of scope**

- Permanent support for every future backend and transparent downgrade.

### Issue: Freeze canonical encodings and publish normative vectors

**Purpose**

Give independent implementations a precise way to verify compatible package
behavior.

**Acceptance criteria**

- [ ] The stable specification defines canonical byte-level encodings and all
  limits.
- [ ] Normative positive and negative vectors cover every stable mode and
  supported backend.
- [ ] Vector provenance and verification procedures are published.
- [ ] Cross-implementation results are recorded.

**Out of scope**

- Stabilizing experimental extensions that have not completed review.

### Issue: Complete parser hardening and fuzzing

**Purpose**

Reduce the risk from malformed, hostile, and resource-exhausting packages
before committing to a stable parser.

**Acceptance criteria**

- [ ] Public-envelope, manifest, and extraction-path parsers have maintained
  fuzz targets.
- [ ] Corpus cases cover every prior parser and extraction security regression.
- [ ] Resource-limit behavior is exercised under adversarial inputs.
- [ ] Findings are fixed with focused regression tests or documented before
  release.

**Out of scope**

- Claims that fuzzing proves the absence of vulnerabilities.

### Issue: Complete cross-platform interoperability testing

**Purpose**

Confirm that stable packages and safe extraction rules behave consistently on
all supported platforms.

**Acceptance criteria**

- [ ] CI verifies normative vectors on every supported platform.
- [ ] Filename, path, collision, permissions, and overwrite behavior is
  documented per platform.
- [ ] Packages created on one supported platform open safely on the others.
- [ ] Unsupported filesystem behavior is documented.

**Out of scope**

- Support guarantees for every filesystem and operating system.

### Issue: Commission and remediate an external security review

**Purpose**

Obtain independent review of package parsing, backend integration, metadata
exposure, key handling, contact trust, and extraction safety.

**Acceptance criteria**

- [ ] Review scope and tested commit are recorded.
- [ ] Findings are fixed with tests or explicitly accepted with rationale.
- [ ] Security documentation and claims reflect review results.
- [ ] No unresolved critical or high-severity findings remain at release.

**Out of scope**

- Claims that an audit guarantees security or covers future changes.

### Issue: Prepare the v1.0 production-readiness decision

**Purpose**

Make a documented release decision based on implementation evidence rather than
the version number alone.

**Acceptance criteria**

- [ ] Stable specification, threat model, operational guidance, recovery
  guidance, and security limitations are complete.
- [ ] Dependency review, interoperability results, fuzzing status, and external
  review remediation are recorded.
- [ ] Release checks pass on the release commit.
- [ ] Public claims accurately distinguish implemented protections,
  assumptions, and limitations.

**Out of scope**

- GUI, relay server, chat, password mode, signatures, and unsupported
  post-quantum security claims.
