# Multi-file and Folder Packages

> [!WARNING]
> PQSend is experimental and unaudited. The current backend is X25519-only and
> not post-quantum-secure. The pre-`v1.0.0` format is unstable.

**Status:** future design note; not implemented or supported.

This document proposes security and format requirements for a future
multi-file and folder package milestone. It is not a wire-format
specification, does not assign identifiers, and does not authorize
implementation.

The current `.pqsend` package-format version `1`, package mode `1`, and
reference CLI remain exactly single-file. This design does not change current
package framing, accepted package bytes, or CLI behavior.

## Why multi-file and folder support matters

Related files often have meaning only as a set. A source tree, document with
assets, exported project, or directory hierarchy is inconvenient and
error-prone to split into independent packages. Users also need empty
directories and relative organization to survive a transfer.

Native multi-entry packages can protect those relationships without requiring
users to create a plaintext archive first. They can also apply one reviewed
path policy, one set of resource limits, and one extraction transaction to the
complete tree.

The feature expands the security boundary substantially. Decrypted paths,
cross-platform collisions, links, filesystem races, partial extraction, and
resource exhaustion all become package-level concerns. It must therefore be a
separate reviewed milestone rather than an extension silently accepted by the
current single-file parser.

## Version and mode decision

Multi-entry packages should use both a **new package-format version** and a
**dedicated generic collection mode**.

- Package-format version `1` and mode `1` must remain permanently single-file.
- A new format version is required because the authenticated inner grammar,
  canonical ordering, limits, and extraction rules all change.
- A dedicated collection mode makes the new content model explicit without
  reinterpreting an existing mode.
- The collection mode should support one or more regular-file and directory
  entries. Separate public modes for "folder", "multiple files", or entry-count
  ranges would leak unnecessary information.
- Identifier values must be assigned only when the complete future format is
  specified and reviewed.

Using only a new mode under format version `1` would conflict with the current
rule that a new layout or behavior requires a new reviewed format version.
Using only a new version without a distinct mode would make the collection
content model less explicit. Readers must reject unsupported versions and
modes without fallback parsing.

A future version may deliberately retain the current fixed-width public
envelope shape, but that decision belongs in the future canonical format
specification. This design does not change the current envelope or framing.

## Public metadata rules

The public envelope must remain minimal. A collection package must not expose:

- the source folder name
- any filename or directory name
- any relative path
- the exact entry count, unless a later privacy review explicitly accepts that
  leak as necessary
- individual file sizes, directory counts, path lengths, entry types,
  permissions, timestamps, or hidden-file status

The new public version, generic collection mode, backend identifier, encrypted
payload length, total package size, and backend-required public material will
remain visible. The collection mode reveals that the package uses the
collection content model, but it must not distinguish a single-entry
collection from a larger tree. Exact encrypted length can still reveal
approximate plaintext size and may permit guesses about structure. Padding is
not proposed here and would require separate design and limits.

Entry count, manifest length, aggregate logical size, and all entry metadata
belong inside the authenticated encrypted payload. Public inspection must not
decrypt them or infer and report an entry count.

The source root name and source path should not be stored even in the encrypted
manifest. Entries are relative to an implicit logical root, and the recipient
chooses the local output-root name. This minimizes metadata and avoids letting
a sender-selected root name choose an extraction destination.

## Encrypted manifest design

The collection format should use a purpose-built, canonical, length-prefixed
binary manifest inside the authenticated encrypted payload. It should not use
tar, zip, or another general archive format by default.

General archive formats carry broad and sometimes ambiguous behavior for
links, permissions, timestamps, special files, path separators, duplicate
entries, extensions, and extraction. Adopting one would require a deliberate
review showing that a tightly constrained canonical profile is safer and
interoperable. Convenience alone is not sufficient justification.

Conceptually, the encrypted plaintext should contain:

1. A fixed inner header with authenticated copies of the public format
   version, package mode, and backend identifier.
2. A bounded manifest length, encrypted entry count, and aggregate regular-file
   byte count.
3. Canonically ordered entry records.
4. Exact regular-file bodies in the same order as their manifest records.
5. Exact end-of-plaintext, with no trailing data.

The future format specification must assign exact field widths and define all
length arithmetic. It must reject unknown entry types, unknown fields,
alternate encodings, impossible lengths, and trailing bytes.

The manifest and all file bodies must be protected and authenticated by the
selected established encryption backend. Per-file hashes are encrypted
consistency checks that bind records to extracted bodies; they are not
signatures or substitutes for backend authentication.

## Entry representation

The first collection version should represent only:

- regular files
- directories

The logical root is implicit and is not an entry. Every non-root directory,
including an empty directory, has an explicit directory record. Every parent
directory of an entry must therefore appear in the manifest.

Each entry record should contain:

- an entry type
- a relative path encoded as a non-empty sequence of path components
- for a regular file, its body length and a SHA-256 consistency hash
- no source absolute path, owner, group, permissions, executable bit,
  timestamp, extended attribute, access-control list, filesystem flag, or
  platform-specific metadata

Directory records have no body. Regular-file bodies appear after the complete
manifest in canonical regular-file record order. Offsets should be inferred
from checked lengths and canonical order rather than independently supplied,
overlapping, or sparse.

Entries must be sorted by a precisely specified component-wise comparison of
their canonical encoded paths, with a parent sorting before its descendants.
Duplicate paths, a file and directory at the same path, a file used as an
ancestor, unsorted records, and missing parent directory records are invalid.

The first version must not preserve executable bits. Extracted regular files
must be created with conservative non-executable permissions subject to local
platform policy and umask. Directories receive only the permissions necessary
for safe local use; source permissions are not restored.

## Path normalization and component rules

Paths must be represented as component sequences, not platform path strings.
The manifest must not encode `/`, `\`, drive-letter syntax, UNC syntax, or
another platform's separator conventions between components.

Each component must be valid UTF-8, in Unicode Normalization Form C (NFC), and
within a documented byte limit. Writers should reject non-NFC input rather
than silently rename it. Readers must independently verify NFC.

Each component must satisfy a portable safety profile at least as strict as
the current single-file filename rules. Reject a component that:

- is empty, `.`, or `..`
- contains `/`, `\`, NUL, an ASCII control character, DEL, or any of
  `< > : " | ? *`
- ends with a dot or space
- case-insensitively matches a Windows reserved device stem, including when
  followed by an extension
- is otherwise identified as unsafe by the future reviewed component profile

An absolute path is impossible in the component-sequence model and any
attempted absolute-path representation must be rejected. Paths with zero
components, excessive components, excessive encoded length, or excessive
depth must also be rejected.

Names must be rejected rather than sanitized. Rewriting authenticated paths
can create collisions, change meaning, or cause different hostile inputs to
select the same output.

## Path traversal prevention

Rejecting absolute paths and `..` is necessary but not sufficient. A future
extractor must:

- validate the complete authenticated manifest before publishing output
- resolve every entry only beneath a caller-selected output root
- reject symlink or other unsafe ancestors encountered during extraction
- use directory-relative, no-follow filesystem operations or equivalent
  platform protections where available
- verify that every created object has the expected type
- fail closed on path replacement, collision, or unexpected filesystem state

Joining a validated string path and then writing it is not an adequate
extraction design. The implementation must account for filesystem replacement
races and document any platform limitations it cannot eliminate.

## Symlink policy

Symlinks must be rejected in the first collection version.

- The format has no symlink entry type.
- Packing must inspect entries without following links and reject any symlink
  encountered in the selected input tree.
- Symlinks to files or directories must not be treated as their targets.
- Packing must use no-follow handles or revalidate type and filesystem identity
  while reading; a pre-scan followed by an unchecked path reopen is not enough.
- Extraction must reject symlink ancestors, symlink destinations, and any
  unexpected symlink created or substituted while extraction is in progress.

Support for links would require a separate design covering target
normalization, containment, cycles, dangling links, platform differences, and
extraction order.

## Hard link policy

The first collection version must not represent or create hard links.

Packing should reject regular files known to have multiple hard links and
reject repeated filesystem identities within the selected input set where the
platform exposes reliable identity and link-count information. Implementations
must document platforms on which complete source hard-link detection is not
feasible and must not claim stronger detection than they provide.

The manifest has no hard-link entry type, and extraction always creates
independent regular files. Any future preservation of hard-link relationships
requires separate security and compatibility review.

## Empty directories

Empty directories matter and must be preserved through explicit directory
records. The source root itself remains implicit and is not restored by name.

Directory records also make parent relationships and extraction ordering
explicit. An empty collection with no entries should be rejected unless a
future use case and extraction meaning are deliberately specified.

## Hidden files

Hidden names such as `.config` are ordinary names and may be represented as
long as each component passes all safety rules. `.` and `..` remain forbidden.

A future directory-packing operation should include safe hidden entries rather
than silently omit them. Ignore files, operating-system hidden attributes, and
tool-specific exclusion rules must not affect package contents unless a later
CLI design makes exclusions explicit to the user.

Hidden attributes are not preserved as metadata. On platforms where hidden
status is an attribute rather than a naming convention, extraction does not
restore that attribute in the first version.

## Unicode normalization

The first collection version should require valid UTF-8 NFC components and
reject non-NFC components. The future format specification must pin the
normalization and case-comparison behavior precisely enough for independent
implementations and test vectors.

Within each directory, sibling names that collide under the specified
portable case-folding comparison must be rejected even if their UTF-8 bytes
differ. Exact duplicate paths are always rejected. A target filesystem may
have additional equivalence or reserved-name rules; extraction must detect and
reject resulting collisions rather than rename entries.

The Unicode version and exact portable collision algorithm remain open review
items because changing either can change which manifests are accepted.

## Cross-platform path differences

The component-sequence representation avoids treating `/` and `\` differently
across platforms. The portable component profile also blocks Windows drive
prefixes, alternate data stream syntax, reserved devices, trailing dots and
spaces, and control characters.

The future implementation must reject, rather than rewrite:

- case-insensitive sibling collisions
- Unicode-equivalent sibling collisions under the specified rules
- file-versus-directory conflicts
- target-filesystem names or paths that cannot be created safely
- paths exceeding either format limits or stricter target-filesystem limits

Platform-specific source metadata is omitted. A package accepted by the
format can still be unextractable on a particular filesystem with stricter
rules. That failure must occur before final publication and must not produce a
silently changed tree.

## Size and resource limits

The collection format must define conservative, format-level acceptance limits
before implementation. At minimum, it needs independent caps for:

- encrypted payload and total package bytes
- authenticated plaintext and manifest bytes
- encrypted entry count
- regular-file count and directory count
- aggregate regular-file bytes and per-file bytes
- component bytes, components per path, total path bytes, and directory depth
- aggregate encoded path bytes and hashing/extraction work

The first implementation is expected to remain non-streaming and should keep a
conservative aggregate plaintext limit comparable to the current single-file
milestone rather than treating `u64` field capacity as an acceptable limit.
Exact values and derived encrypted-payload bounds must be chosen during format
review and covered by boundary vectors.

Limits stored in the manifest remain encrypted. They must be validated with
checked arithmetic before allocation, indexing, body processing, or output
creation. Limits reduce normal denial-of-service exposure but cannot prevent
all CPU, memory, disk, repeated-input, or decompression-style resource attacks.
The first version should not include compression.

## Later streaming migration

The first collection implementation may authenticate and validate the complete
bounded plaintext before extraction, matching the current fail-closed model.
Its manifest-first, sequential-body layout should make a later staged streaming
implementation possible without requiring random body offsets.

Streaming must not mean publishing unauthenticated or partially validated
files. A later implementation may decrypt and hash into a private staging area
with bounded memory, but it must authenticate the complete backend payload,
validate all entry lengths and hashes, and complete extraction checks before
publishing the final output root.

If safe streaming requires chunk records, a different backend contract, new
limits, or a changed inner grammar, it must use another reviewed format version
or mode as appropriate. This design does not promise that the first collection
format can be streamed compatibly.

## Extraction safety

The recommended first-version extraction transaction is:

1. Validate the public envelope and exact package length.
2. Decrypt and authenticate the complete bounded payload.
3. Parse and validate the complete manifest, canonical order, paths, limits,
   body lengths, and hashes without publishing output.
4. Preflight the selected destination and target-filesystem conflicts.
5. Create a private staging directory beside the intended output root.
6. Create directories and regular files beneath staging using no-follow,
   directory-relative operations and conservative permissions.
7. Revalidate expected object types and completed content.
8. Atomically publish the staging directory as a new output root with
   no-replace semantics where the platform provides that operation.

Failure must not publish a final tree that appears complete. Temporary
plaintext cleanup is best effort and cannot guarantee erasure from storage,
memory, swap, backups, or crash artifacts.

Publication must fail if the final root appears during extraction. An ordinary
rename operation that may replace an existing destination is not acceptable.
Platforms without atomic no-replace directory publication need a documented
safe alternative and must state any remaining atomicity limitation.

Special files, devices, sockets, FIFOs, links, sparse-file directives,
extended attributes, access-control lists, and executable permissions are not
represented or restored in the first version.

## Overwrite behavior

The first collection extractor should refuse to extract when the selected
final output root already exists. It should not merge into an existing
directory and should never replace individual files or directories.

This is stricter and easier to reason about than per-entry overwrite prompts.
A future explicit overwrite or merge workflow would require a separate design
for confirmation scope, rollback, conflict handling, links, races, and partial
failure. No overwrite behavior is authorized by this note.

## Test vectors and security-sensitive tests

Before implementation is considered complete, the collection format needs
reviewed deterministic inner-plaintext fixtures plus valid and invalid
encrypted package vectors. The corpus should include:

- nested files and directories, zero-byte files, empty directories, and safe
  hidden names
- canonical NFC names and defined cross-platform comparison cases
- minimum, maximum, and over-limit values for every count, length, depth, and
  aggregate limit
- exact duplicate paths, portable case-fold collisions, Unicode collisions,
  file/directory conflicts, missing parents, unsorted entries, and file
  ancestors
- empty components, `.`, `..`, separators, absolute and drive-like paths,
  invalid UTF-8, non-NFC names, reserved device names, control characters, and
  trailing dots or spaces
- unknown and forbidden entry types, including symlink, hard-link, and special
  file attempts
- malformed lengths, integer overflow cases, truncation, trailing bytes,
  reordered bodies, and hash mismatches
- public-inspection checks demonstrating that names, relative paths, folder
  names, and exact entry count are not public fields
- extraction tests for existing destinations, symlink ancestors, filesystem
  collisions, failed staging, cleanup, and publication
- cross-platform vectors and extraction tests on every supported platform

Encryption is randomized, so newly created ciphertext need not reproduce a
fixed encrypted vector byte-for-byte. Test identities and recipients must be
public fixtures only and never used for real data.

## Compatibility implications

This design leaves current package-format version `1`, mode `1`, framing,
limits, parser behavior, and CLI behavior unchanged.

A future collection-capable release should continue to read supported
single-file packages while dispatching collection packages only under their
new reviewed version and mode. Older readers will reject the new version.
Readers must never reinterpret a collection package as a single-file package
or attempt fallback parsing.

Before collection support is implemented, the milestone must update the
canonical [format specification](../FORMAT.md), [security
model](../SECURITY-MODEL.md), [threat model](../THREAT-MODEL.md),
[compatibility rules](../COMPATIBILITY.md), design decisions, test-vector
index, release documentation, and security-sensitive tests.

Pre-`v1.0.0` packages have no stability promise, but incompatible changes must
still be explicit and reviewed. No migration should decrypt and repack user
data implicitly.

## Open questions

- What exact version and mode identifiers, binary field widths, and canonical
  byte layouts should the future format assign?
- What conservative entry-count, manifest, depth, aggregate-size, and package
  limits should the first non-streaming implementation enforce?
- Which Unicode version and portable case-folding algorithm should define
  collision rejection?
- Can all supported platforms provide sufficiently strong no-follow,
  directory-relative extraction and atomic directory publication semantics?
- On which supported platforms can source hard links and input replacement
  races be detected reliably enough to fail closed?
- Should a future packing workflow accept several unrelated input roots, and
  if so, how are their relative top-level names selected without collisions?
- Should package padding ever be offered to reduce size and structure leakage,
  and what bounded padding policy would avoid new denial-of-service problems?
- Can the proposed manifest-first body layout support safe staged streaming
  with the selected backend, or will streaming require another format version?
- Is refusing every pre-existing output root sufficient, or is a separately
  reviewed explicit merge workflow eventually necessary?

See the [roadmap](../../ROADMAP.md) for milestone ordering. This note does not
authorize multi-file implementation.
