# PQSend

PQSend is a local-first encrypted file package tool. Its goal is to create
portable `.pqsend` packages that can travel through email, cloud storage, USB,
messaging apps, or any other untrusted channel while encryption and decryption
happen locally.

> [!WARNING]
> PQSend is an early experimental project. It does not implement encryption yet
> and must not be used for sensitive real-world data.

The project aims to be serious about security while remaining approachable for
hobbyists and contributors. It will use established, well-reviewed
cryptographic libraries and formats rather than inventing cryptography.

## Current status

This repository currently contains only the initial project skeleton:

- a Rust workspace with `pqsend-core` and `pqsend-cli`
- stub CLI commands that describe the intended user experience
- early, non-normative design and security documentation

There is no encryption, package creation, package extraction, networking, GUI,
password mode, signing, relay service, or post-quantum cryptography.

## Intended command shape

```text
pqsend init
pqsend contact add <name> <public_key_file>
pqsend contact list
pqsend contact fingerprint <name>
pqsend contact verify <name>
pqsend pack <input> --to <contact>
pqsend open <package> --out <directory>
pqsend inspect <package>
```

All commands are currently stubs that exit successfully after printing a clear
message.

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
