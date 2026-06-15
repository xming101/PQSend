# PQSend

PQSend is an experimental encrypted package format and Rust reference CLI for
private file delivery. This repository is the official home of the `.pqsend`
format.

> [!WARNING]
> PQSend is:
>
> - experimental and unaudited
> - X25519-only for now
> - not yet post-quantum-secure
> - built around an unstable package format
> - not for production secrets yet

## What is a `.pqsend` package?

A `.pqsend` package is a portable encrypted file that can be delivered through
an unrelated channel such as email, cloud storage, removable media, or a
messaging app. Package creation and opening happen locally; PQSend does not
provide the delivery channel.

The current format contains exactly one file encrypted for exactly one age
X25519 recipient. It has a strict 20-byte public envelope followed by an
authenticated encrypted payload. The original filename, file contents, file
size, and file hash are inside the encrypted internal manifest rather than the
public envelope.

The public package bytes still reveal the total package size, format version,
single-file mode, age v1 X25519 backend, and use of an X25519 recipient stanza.
The outer `.pqsend` filename and transport metadata are outside the format's
protection.

The format is versioned and has an explicit backend identifier so future
versions can evaluate backend agility and reviewed hybrid post-quantum
cryptography. Current packages do not provide post-quantum security.

## What the reference CLI does today

The Rust reference CLI currently:

- generates one age X25519 identity and matching public recipient
- creates a one-file `.pqsend` package for one explicit recipient or local
  contact
- inspects only the fixed public package envelope
- opens, authenticates, validates, and extracts one package
- manages a local recipient/contact trust store with recipient-bound
  fingerprint verification
- prints local, human-readable receipts after successful package creation and
  opening
- refuses implicit overwrite and rejects unsafe extracted filenames

Receipts explain selected facts about a completed local operation. They are not
embedded in packages and are not signatures, certificates, delivery proof, or
proof of identity.

## Quick start

Install the stable Rust toolchain and run these commands from the repository
root.

Generate one private identity and its matching public recipient:

```sh
cargo run -p pqsend-cli -- keygen \
  --out identity.txt \
  --public-out recipient.txt
```

Keep `identity.txt` secret. Give only `recipient.txt` to a sender.

Create and inspect a package:

```sh
cargo run -p pqsend-cli -- pack report.pdf \
  --recipient-file recipient.txt \
  --out pqsend-transfer-001.pqsend

cargo run -p pqsend-cli -- inspect pqsend-transfer-001.pqsend
```

Open the package into an output directory:

```sh
cargo run -p pqsend-cli -- open pqsend-transfer-001.pqsend \
  --identity-file identity.txt \
  --out opened
```

The CLI also supports a local contact workflow:

```sh
cargo run -p pqsend-cli -- init
cargo run -p pqsend-cli -- contact add bob recipient.txt
cargo run -p pqsend-cli -- contact fingerprint bob
cargo run -p pqsend-cli -- contact verify bob
cargo run -p pqsend-cli -- pack report.pdf \
  --to bob \
  --out pqsend-transfer-002.pqsend
```

`contact verify` interactively requires the exact full fingerprint after it has
been compared through an independent authenticated channel. Unverified
contacts are blocked by default.

## Repository responsibilities

This repository is the official home of the experimental `.pqsend` package
format and contains:

- the sole source of truth for the implemented package byte format in
  [`docs/FORMAT.md`](docs/FORMAT.md)
- the security model, threat model, contacts model, receipts model, and
  compatibility rules
- the test-vector publication area and rules for valid and invalid vectors
- `pqsend-core`, the Rust reference implementation of package parsing,
  creation, backend integration, and local contact state
- `pqsend-cli`, the Rust reference CLI for the current package workflows
- security-sensitive package, backend, contact, and CLI tests

[`SPEC.md`](SPEC.md) is retained only as a short compatibility pointer for old
links. Independent implementations should follow
[`docs/FORMAT.md`](docs/FORMAT.md) and the compatibility documentation and
reject unsupported or non-canonical packages rather than relying on reference
CLI behavior alone.

## Security properties

Within its documented assumptions, the current design aims to provide:

- encrypted file contents and original filename for the selected X25519
  recipient
- a minimal, fixed public envelope with no plaintext original filename
- complete backend authentication before publishing extracted plaintext
- strict parsing that rejects malformed, truncated, unsupported, or trailing
  package data
- extraction checks that prevent path traversal through the authenticated
  filename
- refusal to overwrite existing key, package, or extracted files
- local contact verification bound to the exact canonical recipient key

PQSend does not invent cryptography. The current backend adapter delegates
recipient encryption and authenticated payload protection to the Rust `age`
crate. These are scoped design properties, not guarantees; security also
depends on the backend, implementation, dependencies, endpoint security,
recipient-key verification, and private-key protection.

## Current limitations

- one file and one recipient per package
- 64 MiB maximum input file size
- age v1 X25519 backend only; no post-quantum protection
- no stable package compatibility before `v1.0.0`
- no external security audit
- no folders, multiple recipients, signatures, password mode, or sender
  authenticity
- no protection for compromised endpoints, private keys, or local contact
  state
- no hiding of total size, transfer timing, routing metadata, or the outer
  package filename

## What PQSend is not

PQSend is not:

- mainly a post-quantum encryption CLI; the current backend is X25519-only
- an `age` replacement; the reference implementation uses `age` as its current
  encryption backend
- a general-purpose encryption command
- a messaging app
- a cloud sending service or required relay
- an anonymity system or proof-of-delivery system

## Roadmap

Near-term work focuses on format and parser hardening, malformed-package and
resource-limit testing, compatibility and migration-policy hardening, broader
cross-platform package test vectors, and independent review.

Later milestones may evaluate folder and multiple-recipient package versions,
optional authenticity features, backend agility, and a reviewed hybrid
post-quantum backend. Future features require explicit design and
security-model review and must not be described as properties of current
packages.

See the [roadmap](ROADMAP.md) for milestone boundaries.

## Documentation

Start here, in this order:

1. [Package format](docs/FORMAT.md)
2. [Security model](docs/SECURITY-MODEL.md)
3. [Threat model](docs/THREAT-MODEL.md)
4. [Local contacts and recipient trust](docs/CONTACTS.md)
5. [Local security receipts](docs/RECEIPTS.md)
6. [Compatibility rules](docs/COMPATIBILITY.md)
7. [Test vectors](test-vectors/README.md)
8. [Roadmap](ROADMAP.md)
9. [Changelog](CHANGELOG.md)

The [documentation index](docs/README.md) also lists design decisions, future
design notes, release records, implementation notes, and retained compatibility
pointers.

## Contributing and security

Do not invent cryptography or add behavior outside the relevant reviewed
milestone. Behavior changes must include security-sensitive tests and matching
updates to the canonical format, security, threat-model, compatibility, and
design-decision documentation. Keep the top-level compatibility pointers
accurate when their targets or summaries change.

Before considering a change complete, run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Read [SECURITY.md](SECURITY.md) before reporting a security issue.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
