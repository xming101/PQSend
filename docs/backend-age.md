# Experimental age Backend Adapter

PQSend currently uses the Rust [`age`](https://crates.io/crates/age) crate as
its experimental `v0.1` encryption backend. The adapter lives in
`pqsend-core` and provides only binary age v1 encryption to exactly one X25519
recipient and decryption with exactly one X25519 identity.

This adapter is separate from the `.pqsend` package framing layer. The package
layer calls it to encrypt and authenticate the complete inner plaintext; the
adapter itself does not define framing, integrate contacts, or change CLI
behavior.

## Why the Rust age crate

PQSend does not invent cryptography or manually compose low-level cryptographic
primitives. The adapter delegates recipient encryption, authenticated payload
encryption, parsing, and key handling to the `age` crate. It uses age's public
identity policy hook and `age-core` stanza types only to reject unsupported
recipient modes before decryption.

PQSend also avoids shelling out to `age` or `rage`. Using the Rust crate keeps
the backend boundary explicit, avoids executable-discovery and subprocess
behavior, and allows typed errors and focused tests without parsing command
output.

The `age` crate is pre-`1.0` and describes itself as a beta release for testing
purposes. PQSend therefore treats this backend as experimental and pins its
resolved dependency in `Cargo.lock`.

## Deliberately narrow modes

The adapter accepts only:

- binary age v1 output
- one age X25519 recipient for encryption
- one age X25519 identity for decryption

The `age` dependency has default features disabled. Plugin, SSH, ASCII armor,
async, and CLI support are not enabled. The adapter does not expose
passphrase/scrypt encryption or multiple-recipient encryption. Decryption
rejects ciphertext unless its header contains exactly one X25519 recipient
stanza plus the age format's permitted GREASE stanzas.

X25519 is not post-quantum-secure. This adapter must not be described as
post-quantum protection or harvest-now-decrypt-later resistance. A reviewed
post-quantum or hybrid backend remains a later roadmap item.

## Authentication and errors

Encryption always calls the age stream writer's `finish()` method. Decryption
authenticates the complete plaintext into an internal memory buffer and returns
it only after authentication succeeds. Malformed, tampered, truncated,
wrong-key, unsupported-mode, and multiple-recipient ciphertext therefore fails
without returning plaintext.

Errors are deliberately redacted. They distinguish invalid recipient keys,
invalid identity keys, no matching identity, invalid or tampered ciphertext,
encryption failure, and I/O failure without including key material or backend
error details.

Buffering authenticated plaintext prevents partial plaintext from escaping on
failure, but it also means decryption memory use grows with plaintext size.
The `v0.1` package layer enforces documented package limits and validates the
returned inner plaintext before exposing it. Streaming and filesystem
extraction remain future work.

## Metadata exposure

Binary age data exposes that the age backend is in use, the recipient stanza
type (`X25519`), and approximate encrypted payload size. X25519 recipient
stanzas are anonymous, but transport metadata and approximate size remain
visible. The `.pqsend` public envelope also exposes its exact encrypted payload
length while keeping the original filename inside the encrypted plaintext.
