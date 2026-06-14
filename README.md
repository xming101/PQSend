# PQSend

PQSend is an experimental encrypted package format and reference CLI for private file delivery.

> [!WARNING]
> PQSend is experimental and unaudited. It currently supports only age v1 with
> X25519, is not yet post-quantum-secure, and is not ready for sensitive
> real-world data. The `.pqsend` package format is unstable and may change
> incompatibly before `v1.0.0`.

PQSend creates portable `.pqsend` files that can travel through email, cloud
storage, USB, messaging apps, or other channels while package creation and
opening happen locally. Its focus is hidden public metadata, local recipient
trust, local security receipts, and a future post-quantum migration path.

## Why PQSend exists

PQSend does not claim stronger cryptography than its encryption backend. The
current implementation delegates recipient encryption and authenticated
payload protection to the Rust [`age`](https://age-encryption.org/) crate.
PQSend adds an opinionated package and user-safety layer around that backend:

- a strict `.pqsend` package envelope with minimal, fixed public metadata
- an encrypted internal manifest containing the original filename
- an original filename that is hidden from public package metadata
- a local recipient trust store with recipient-bound verification
- local, human-readable security receipts
- a reference CLI with conservative package creation and extraction behavior
- package format documentation and deterministic format tests, with published
  cross-platform fixture test vectors still planned

The versioned package envelope and backend identifier provide a path for
evaluating a reviewed future post-quantum or hybrid backend. They do not make
current X25519 packages post-quantum-secure.

## Current features

- `keygen` for one age X25519 identity and matching public recipient file
- `pack` to create a one-file package for one explicit recipient or local
  contact
- `open` to decrypt, validate, and restore the authenticated original filename
- `inspect` to display only the fixed public envelope and package size
- a fixed 20-byte public envelope and encrypted internal manifest
- an explicit key-file workflow
- a contact-backed workflow with local fingerprints and verification state
- local security receipts for successful package creation and opening
- overwrite refusal and safe single-file extraction checks

## Quick start

Install the stable Rust toolchain and run commands from the repository root.

Generate one private age X25519 identity and its matching public recipient:

```sh
cargo run -p pqsend-cli -- keygen \
  --out identity.txt \
  --public-out recipient.txt
```

Keep `identity.txt` secret. Give only `recipient.txt` to a sender.

Create a package using the explicit recipient file:

```sh
cargo run -p pqsend-cli -- pack report.pdf \
  --recipient-file recipient.txt \
  --out pqsend-transfer-001.pqsend
```

Inspect the package's public envelope without decrypting it:

```sh
cargo run -p pqsend-cli -- inspect pqsend-transfer-001.pqsend
```

Open the package into a new or existing output directory:

```sh
cargo run -p pqsend-cli -- open pqsend-transfer-001.pqsend \
  --identity-file identity.txt \
  --out opened
```

Package creation, key generation, and extraction refuse to overwrite existing
files. The current one-file input limit is 64 MiB.

### Contact-backed workflow

Contacts are local convenience aliases for canonical age X25519 recipients.
Initialize the local store, add a recipient, display its fingerprint, and
verify the full fingerprint after comparing it through an independent
authenticated channel:

```sh
cargo run -p pqsend-cli -- init
cargo run -p pqsend-cli -- contact add bob recipient.txt
cargo run -p pqsend-cli -- contact fingerprint bob
cargo run -p pqsend-cli -- contact verify bob
```

Create a package for the verified contact:

```sh
cargo run -p pqsend-cli -- pack report.pdf \
  --to bob \
  --out pqsend-transfer-002.pqsend
```

Unverified contacts are blocked by default. `--allow-unverified` is an explicit
one-command override and is recorded in the local receipt. Contact verification
is a local decision about an exact recipient key; it is not identity proof, a
signature, proof of delivery, or proof of key control.

## Metadata privacy

### Hidden from public package metadata

- file contents
- original filename and authenticated internal manifest
- encrypted file hash
- contact alias, fingerprint, and verification status
- sender identity, notes, and timestamps, which are not package fields

Contact aliases and fingerprints are not placed anywhere in the package,
including the encrypted manifest. They may appear in local terminal output and
local receipts.

### Still visible

- total package size and approximate plaintext size
- transfer timing and other transport metadata outside PQSend
- the outer `.pqsend` filename chosen by the user
- package format version, single-file mode, and age v1 X25519 backend from the
  public envelope
- the use of age and an X25519 recipient stanza in the encrypted payload

Choose an outer package filename unrelated to the original file when the
original name must not be exposed by the transport.

## Security model

PQSend avoids custom cryptography. The current backend adapter uses the Rust
`age` crate directly for binary age v1 encryption to exactly one X25519
recipient and decryption with exactly one X25519 identity. Security depends on
the backend, implementation correctness, dependencies, recipient-key
verification, endpoint security, and private-key protection.

Opening validates the public envelope before decryption, authenticates and
validates the complete inner plaintext before publishing output, rejects unsafe
filenames, prevents path traversal through the authenticated filename, and
refuses implicit overwrite.

Local security receipts summarize selected recipient and completed checks. They
are command output only, are not embedded in packages, and are not signatures
or external proof. Successful creation and opening receipts include the exact
package SHA-256 and an explicitly local receipt time; neither proves identity,
authorship, delivery, or package creation time.

## Limitations

- one file and one recipient per package
- no folder or multi-file packages yet
- no multiple-recipient packages yet
- no post-quantum cryptography yet
- no signatures or proof of authorship
- no password mode
- no GUI, networking, Wi-Fi transfer, or relay service
- no stable package-format compatibility before `v1.0.0`
- no external security audit

PQSend provides private file delivery, not anonymous sending. It does not hide
transport-level sender, recipient, timing, or size metadata, and it does not
protect compromised endpoints or private keys.

## Documentation

- [Draft specification](SPEC.md)
- [Package format](docs/FORMAT.md)
- [Security model](docs/SECURITY-MODEL.md)
- [Threat model](docs/THREAT-MODEL.md)
- [Contact trust store](docs/CONTACTS.md)
- [Security receipts](docs/RECEIPTS.md)
- [age backend boundary](docs/backend-age.md)
- [Design decisions](docs/design-decisions.md)
- [Roadmap](ROADMAP.md)
- [Changelog](CHANGELOG.md)

## Development

Run the repository completion checks:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Read [SPEC.md](SPEC.md), the [security model](docs/SECURITY-MODEL.md), and the
[threat model](docs/THREAT-MODEL.md) before proposing behavior changes.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
