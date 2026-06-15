# Threat Model

The canonical threat model is [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
This top-level summary is retained for existing links and contributor
workflows.

PQSend is experimental, unaudited, X25519-only, not post-quantum-secure, and
not ready for sensitive real-world data. The `.pqsend` package format is
unstable before `v1.0.0`.

At a high level, PQSend is designed to keep file contents and the internal
original filename confidential from package holders without the recipient's
private key, reject invalid or truncated package bytes, and block unverified
contacts by default. It does not protect compromised endpoints or keys, hide
package size or transfer metadata, provide anonymity or identity proof, prove
authorship or delivery, or protect the current X25519 backend from quantum
attacks.

Local CLI receipts may expose package paths, package hashes, local receipt
times, contact aliases and verification outcomes, and restored output paths in
terminal logs. Pack receipts do not print contact fingerprints or recipient
keys. Receipts are not package metadata, cryptographic proof, or cryptographic
certificates and do not prove identity, authorship, delivery, or package
creation time.

See also:

- [Security model](docs/SECURITY-MODEL.md)
- [Package format](docs/FORMAT.md)
- [Contact trust store](docs/CONTACTS.md)
- [Security receipts](docs/RECEIPTS.md)
