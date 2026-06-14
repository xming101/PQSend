# PQSend

PQSend is an experimental, local-first encrypted file-sending package layer for
humans. It is intended to create portable `.pqsend` files that can travel
through email, cloud storage, USB, messaging apps, or other untrusted channels
while encryption and decryption happen locally.

PQSend is not trying to provide stronger cryptography than tools such as
[`age`](https://age-encryption.org/). Its intended value is an opinionated
package and user-safety layer around established encryption backends:

- a `.pqsend` package format with minimal public metadata
- an encrypted internal manifest, including the original filename
- encrypted filenames and, in a later milestone, encrypted folder structure
- a contact book with explicit verification status
- human-readable security receipts
- safe defaults for package creation and extraction
- local-first operation, no telemetry, and no required server

> [!WARNING]
> `v0.1.0-alpha.1` is experimental, unaudited, X25519-only, not
> post-quantum-secure, and not ready for sensitive real-world data. The
> `.pqsend` package format is unstable and may change incompatibly before
> `v1.0.0`.

## Security approach

PQSend avoids custom cryptography. The experimental `pqsend-core` backend
adapter uses the Rust `age` crate directly for binary age v1 encryption to one
X25519 recipient and decryption with one X25519 identity. It does not shell out
to an external executable. Security depends on the backend, correct
implementation, dependency security, recipient-key verification, and private-key
protection.

The design is intended to be post-quantum-ready through versioned packages and
backend agility. That is an evolution goal, not a claim that current or early
PQSend packages resist cryptographically relevant quantum computers. A future
hybrid future-resistant backend would require its own review, specification,
tests, and threat-model update.

## Current status

The repository currently contains an experimental `v0.1` package core and CLI
workflow plus a separate local contact book:

- a Rust workspace with `pqsend-core` and `pqsend-cli`
- working `init` and `contact` CLI commands
- a tested binary age v1 X25519 encryption/decryption adapter
- strict single-file `.pqsend` package creation, opening, and public inspection
- explicit age X25519 key-file generation and package CLI commands
- early, non-normative design and security documentation

There is no contact-backend integration, folder support, multiple-recipient
support, networking (including Wi-Fi transfer), GUI, password mode, signing,
relay service, chat, sender identity management, or post-quantum protection.
The current X25519 backend is not post-quantum-secure.

The `v0.1` milestone is deliberately narrow: encrypt and decrypt one file for
one recipient using an existing backend and a draft `.pqsend` package.
Folder support, multiple recipients, signatures, password mode, GUI, relay
server, Wi-Fi transfer, and chat are out of scope until later milestones.

## Contact book

The implemented local contact commands are:

```text
pqsend init
pqsend contact add <name> <public_key_file>
pqsend contact list
pqsend contact fingerprint <name>
pqsend contact verify <name>
```

`pqsend init` creates an experimental `contacts.toml` store below the
OS-appropriate config directory, approximately:

- Linux: `~/.config/pqsend/`
- macOS: `~/Library/Application Support/pqsend/`
- Windows: `%APPDATA%\pqsend\`

Public keys are treated as opaque UTF-8 text. PQSend normalizes line endings,
trims leading and trailing whitespace, and calculates an uppercase grouped
SHA-256 fingerprint over the normalized text. SHA-256 is used only for contact
identification here; it is not encryption. `contact verify` only flips a local
manual trust flag and does not prove identity or perform trust-on-first-use.
Contact names are exact and case-sensitive.

The contact store format is experimental and may change without migration
support. It is local plaintext state, so protect it using normal operating
system account and filesystem controls.

## Explicit key-file quick start

Generate one private age X25519 identity and its matching public recipient:

```sh
cargo run -p pqsend-cli -- keygen \
  --out identity.txt \
  --public-out recipient.txt
```

Keep `identity.txt` secret. Give only `recipient.txt` to a sender. Encrypt one
regular file of at most 64 MiB into an explicitly named package:

```sh
cargo run -p pqsend-cli -- pack report.pdf \
  --recipient-file recipient.txt \
  --out pqsend-transfer-001.pqsend
```

The outer package filename is public transport metadata. If you want to avoid
leaking the original filename, do not name the outer `.pqsend` package after
the original file. Inspect only its public 20-byte envelope, then decrypt it:

```sh
cargo run -p pqsend-cli -- inspect pqsend-transfer-001.pqsend

cargo run -p pqsend-cli -- open pqsend-transfer-001.pqsend \
  --identity-file identity.txt \
  --out opened
```

Package creation, key generation, and extraction refuse to overwrite existing
files. `open` restores the authenticated original basename only after complete
decryption and validation, rejects a symbolic link as the final output-directory
component, and creates a missing output directory privately on Unix. Contacts
are not used by this workflow.

See [docs/backend-age.md](docs/backend-age.md) for the implemented backend
boundary and limitations. See
[the `v0.1.0-alpha.1` release notes](docs/releases/v0.1.0-alpha.1.md) for the
included scope and known limitations.

## Development

Install the stable Rust toolchain, then run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Read [SPEC.md](SPEC.md) and [THREAT_MODEL.md](THREAT_MODEL.md) before proposing
behavior changes. See [ROADMAP.md](ROADMAP.md) for the planned sequence of work.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
