# Reference GUI

> [!WARNING]
> PQSend is experimental and unaudited. The current backend is X25519-only and
> not post-quantum-secure. The pre-`v1.0.0` format is unstable.

**Status:** future design note; no GUI is implemented or supported.

This note describes a possible future local reference application. It does not
authorize GUI implementation, add dependencies, change CLI behavior, or change
the `.pqsend` package format.

## Purpose

A future reference GUI could make creating, inspecting, and opening `.pqsend`
packages easier for people who do not want to use a terminal. It must remain a
local-first interface over the same reviewed package behavior, format, and
security model used by the reference CLI.

The GUI must not create a second package format or silently add different
security semantics. The Rust CLI remains the reference implementation for now.
GUI work may begin only in its reviewed milestone after the necessary core
crate boundaries, security behavior, and test plan are agreed.

## Possible user experience

The exact interaction design remains open, but a future GUI could provide
local workflows to:

- choose a file, or choose a folder after folder packages are separately
  designed and implemented
- choose a local contact and clearly show that contact's verification state
- create a `.pqsend` package without implicitly overwriting an existing file
- inspect a `.pqsend` package's public metadata without decrypting it
- open a `.pqsend` package locally, validate it, and extract it without
  implicit overwrite or path traversal
- show conservative local receipts after successful create and open actions
- add, view, update, and remove local contacts
- display and explicitly verify full contact fingerprints

Inspection must preserve the current distinction between public inspection and
authorized opening. It must not present encrypted filenames, contents, contact
information, or other hidden fields as available before decryption.

Destructive or trust-changing actions must require clear user confirmation.
Warnings about unverified contacts, experimental status, the current
X25519-only backend, and overwrite refusal must remain visible and actionable
rather than being hidden behind convenience flows.

## Security rules

The future GUI must preserve the same security boundaries as the package core
and CLI:

- no telemetry
- no account system
- no cloud sync
- no relay by default; any future relay requires a separate design and review
- no plaintext file contents, filenames, private keys, contacts, or receipts
  leave the device through GUI behavior
- private keys are never displayed by default
- contact verification remains an explicit full-fingerprint comparison and
  user decision
- unverified-contact warnings and any one-operation override remain explicit
- receipts remain conservative local summaries and must not imply signatures,
  identity, authorship, delivery, or external proof
- public package metadata remains minimal
- safe extraction, path traversal prevention, and overwrite refusal remain
  mandatory

The application must clearly disclose the implemented backend and project
status without exaggerated security claims. Local GUI state, notifications,
logs, crash reports, recent-file lists, and operating-system integrations must
be reviewed for metadata leakage before release. Automatic crash reporting is
telemetry and is therefore prohibited.

## Architecture options

Tauri or a native Rust GUI may be evaluated later. The choice should minimize
the trusted surface, preserve cross-platform safety behavior, and avoid adding
network capabilities that the local application does not need.

If crate boundaries allow it, the GUI should call `pqsend-core` directly for
package creation, inspection, opening, validation, and receipt facts. Contact
operations should likewise use reviewed shared Rust APIs rather than duplicate
trust logic in the interface layer.

The future GUI should avoid shelling out to the CLI where possible. Direct core
calls provide clearer typed boundaries and avoid command construction,
terminal-output parsing, and subprocess-environment risks. The GUI must not
invent cryptography or bypass backend, parser, extraction, contact, or receipt
rules.

No major workspace rewrite is needed now. Any later crate-boundary adjustment
should be small, reviewed, and justified by shared behavior rather than by UI
framework preferences.

## Out of scope for the first GUI

The first GUI must not include:

- a mobile application
- cloud sync
- a server relay
- messaging or chat
- QR-based contact or key exchange unless separately designed and reviewed
- a Web of Trust
- a new package format or GUI-only package behavior

## Testing needs

Before a GUI can be considered a reference application, tests must cover:

- package compatibility between GUI-created packages and the CLI in both
  directions
- consistent receipt facts and conservative receipt wording across interfaces
- absence of plaintext filename, contact, receipt, and other unintended
  metadata leakage
- prominent contact-verification warnings, explicit verification actions, and
  unverified-contact override behavior
- the same malformed-package rejection, resource limits, path traversal
  prevention, and overwrite refusal expected from the core and CLI
- failure behavior that does not publish partial plaintext or weaken existing
  checks

Platform-specific integration testing must also review filesystem dialogs,
notifications, logs, recent-file behavior, and application state for plaintext
or private-key exposure.

See the [roadmap](../../ROADMAP.md) for milestone ordering. This note does not
authorize GUI implementation.
