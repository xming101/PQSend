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
> PQSend is experimental, incomplete, and not ready for sensitive real-world
> data. The repository does not implement encryption yet.

## Security approach

PQSend avoids custom cryptography. Early versions should use an existing,
well-known encryption backend such as `age` or `rage` rather than manually
composing cryptographic primitives. Security depends on the selected backend,
correct implementation, dependency security, contact-key verification, and
private-key protection.

The design is intended to be post-quantum-ready through versioned packages and
backend agility. That is an evolution goal, not a claim that current or early
PQSend packages resist cryptographically relevant quantum computers. A future
hybrid future-resistant backend would require its own review, specification,
tests, and threat-model update.

## Current status

The repository currently contains the `v0.0.1` project skeleton plus an
experimental local contact book:

- a Rust workspace with `pqsend-core` and `pqsend-cli`
- working `init` and `contact` CLI commands
- stub package commands that describe the intended package user experience
- early, non-normative design and security documentation

There is no encryption, package creation, package extraction, networking, GUI,
password mode, signing, relay service, chat, sender identity, key generation, or
post-quantum protection.

The `v0.1` milestone is deliberately narrow: encrypt and decrypt one file for
one recipient using a reviewed existing backend and a draft `.pqsend` package.
Folder support, multiple recipients, signatures, password mode, GUI, relay
server, and chat are out of scope until later milestones.

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

## Intended package commands

These longer-term package commands remain stubs:

```text
pqsend pack <input-file> --to <contact>
pqsend open <package> --out <directory>
pqsend inspect <package>
```

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
