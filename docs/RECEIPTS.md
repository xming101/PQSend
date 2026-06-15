# Security Receipts

> [!WARNING]
> PQSend is experimental, unaudited, X25519-only, not post-quantum-secure, and
> unstable before `v1.0.0`.

Security receipts are local, human-readable CLI output printed after successful
`pack` and `open` operations. They explain selected facts about the
experimental `.pqsend` package format, the completed operation, and local
recipient selection.

Receipts are not cryptographic proofs. They are not signatures and do not prove
identity, authorship, delivery, receipt, endpoint security, or when a package
was created. They are not cryptographic certificates or a stable
machine-readable API. Interpret them together with the [threat
model](THREAT-MODEL.md).

## Storage boundary

Receipts are printed to standard output. PQSend does not embed them in the
public envelope, encrypted internal manifest, or any other part of a `.pqsend`
package. `inspect` stays focused on safe public package metadata and does not
print a receipt.

Terminal capture, shell logging, or manually saved output can retain receipt
fields as local plaintext metadata. Create receipts contain the package path,
and contact-backed receipts contain the local alias and verification outcome.
Open receipts contain the restored output path and therefore the decrypted
original filename.

The receipt time is generated from the local system clock after the successful
operation. It is labeled `Local receipt time (Unix seconds; not package
metadata)` because it is neither authenticated package metadata nor a package
creation timestamp.

## Package creation receipt

A successful `pack` receipt includes:

- action: package created
- `.pqsend` format, format version `1`, and single-file package mode
- fixed 20-byte v0.1 public envelope
- age v1 X25519 backend and explicit not-post-quantum-secure status
- confirmation that the original filename is hidden in package metadata and
  the internal manifest is encrypted
- recipient source: explicit recipient file or local contact
- contact verification: verified, unverified override, or not applicable
- package path
- SHA-256 of the completed package bytes, computed after writing
- local receipt time, explicitly labeled as not package metadata
- for a local contact, its alias and verification outcome at creation time
- a prominent warning when `--allow-unverified` was used
- known public leakage: package size, transfer timing, and the outer package
  filename
- a reminder that the transfer channel does not need to be trusted with
  plaintext
- a warning that PQSend is experimental, unaudited, and uses an unstable
  format

Contact verification status records local contact-store state at creation time.
It does not establish identity or key control. Pack receipts do not print
contact fingerprints or recipient keys. Explicit contact commands such as
`contact fingerprint` and `contact verify` are the intended way to display and
compare full fingerprints.

## Package opening receipt

A successful `open` receipt includes:

- action: package opened
- `.pqsend` format, format version `1`, and single-file package mode
- age v1 X25519 backend and explicit not-post-quantum-secure status
- successful decryption and integrity verification by backend authentication
- validated inner manifest and restored original filename
- restored output path
- package path and SHA-256 of the opened package bytes
- local receipt time, explicitly labeled as not package metadata
- a warning that sender identity and authorship are not verified because PQSend
  does not implement signatures
- a warning that PQSend is experimental, unaudited, and uses an unstable
  format

## Interpreting the package hash

The package SHA-256 identifies the exact package bytes observed locally. It can
help compare two local copies and debug accidental changes. It does not prove
who created the package, whether it was delivered, or whether a separately
communicated hash is trustworthy.

See the [security model](SECURITY-MODEL.md) and [threat
model](THREAT-MODEL.md) for the broader trust and metadata boundaries.
