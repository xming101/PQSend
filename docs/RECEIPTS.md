# Security Receipts

Security receipts are local, human-readable CLI output printed after successful
`pack` and `open` operations. They summarize the package bytes and selected
local decisions at the end of an operation.

Receipts are not cryptographic proofs. They are not signatures and do not prove
identity, authorship, delivery, receipt, endpoint security, or when a package
was created. Interpret them together with the [threat model](THREAT-MODEL.md).

## Storage boundary

Receipts are printed to standard output. PQSend does not embed them in the
public envelope, encrypted internal manifest, or any other part of a `.pqsend`
package. `inspect` stays focused on safe public package metadata and does not
print a receipt.

Terminal capture, shell logging, or manually saved output can retain receipt
fields as local plaintext metadata. Create receipts contain the package path
and contact-backed receipts contain the local alias and fingerprints. Open
receipts contain the restored output path and therefore the decrypted original
filename.

The receipt time is generated from the local system clock after the successful
operation. It is labeled `Local receipt time (Unix seconds; not package
metadata)` because it is neither authenticated package metadata nor a package
creation timestamp.

## Package creation receipt

A successful `pack` receipt includes:

- operation: package creation
- package path
- SHA-256 of the completed package bytes, computed after writing
- local receipt time, explicitly labeled as not package metadata
- package format version and single-file mode
- age v1 X25519 backend and explicit X25519-only, not-post-quantum status
- whether the recipient source was an explicit recipient file or contact alias
- for a contact, the local alias, full and short fingerprints, and local
  verification status at creation time
- a prominent warning when `--allow-unverified` was used
- confirmation that the original filename is hidden from public package
  metadata and the internal manifest is encrypted
- known leakage: package size, transfer timing outside PQSend, and the outer
  package filename chosen by the user

Contact verification status records local contact-store state at creation time.
It does not establish identity or key control. The full fingerprint remains the
authoritative comparison value; the short fingerprint is display-only.

## Package opening receipt

A successful `open` receipt includes:

- operation: open/decrypt
- package path and SHA-256 of the opened package bytes
- local receipt time, explicitly labeled as not package metadata
- validated package format version, single-file mode, and age v1 X25519 backend
- integrity verified after successful authenticated opening and inner checks
- restored output path
- a warning that sender identity and authorship are not verified because PQSend
  does not implement signatures

## Interpreting the package hash

The package SHA-256 identifies the exact package bytes observed locally. It can
help compare two local copies and debug accidental changes. It does not prove
who created the package, whether it was delivered, or whether a separately
communicated hash is trustworthy.

See the [security model](SECURITY-MODEL.md) and [threat
model](THREAT-MODEL.md) for the broader trust and metadata boundaries.
