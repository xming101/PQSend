# Experimental v0-alpha Vectors

This directory contains the initial experimental vectors for package-format
version `1`, single-file mode `1`, and age v1 X25519 backend `1`.

The vectors define current Rust reference behavior, not a pre-v1 stability
promise. They may change before `v1.0.0`.

## Metadata

[`manifest.toml`](manifest.toml) records each vector's name, purpose, expected
result, format version, mode, backend, test-identity availability, expected
restored filename and plaintext SHA-256 where valid, expected failure reason
where invalid, and SHA-256 of the exact vector bytes.

Optional expected fields are omitted when they do not apply.

## Fixture keys

[`test-identity.txt`](test-identity.txt) and
[`test-recipient.txt`](test-recipient.txt) are deliberately public test
fixtures. They are included only to open the encrypted package snapshots and
exercise interoperability.

**Never use these fixture keys for real secrets.** They are not private, do
not protect confidentiality, and contain no personal data.

## Vector kinds

- Public-envelope `.bin` vectors exercise the deterministic 20-byte envelope
  codec.
- Inner-plaintext `.bin` vectors expose small synthetic authenticated
  plaintext structures so strict inner parsing can be tested safely. They are
  not public `.pqsend` package bytes.
- End-to-end `.pqsend` vectors exercise fixed encrypted package snapshots.

The public-envelope and inner-plaintext vectors are deterministic. Encrypted
package vectors were generated through the Rust reference implementation and
depend on encryption randomness; newly generated ciphertext is not expected
to byte-match them.

See the parent [test-vector index](../README.md) and the machine-readable
manifest for the complete expectations.
