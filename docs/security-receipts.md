# Security Receipts

Security receipts are a future local, human-readable record of selected PQSend
operations. They are intended to make important choices and checks visible
without asking users to interpret cryptographic internals.

Receipts are not implemented and are out of scope for `v0.1`.

## Intended questions

A receipt may help a user answer:

- which local contact and verification status were used?
- which package format, mode, and encryption backend were processed?
- which integrity, resource-limit, path-safety, and overwrite checks completed?
- when did the local operation complete?

## Trust limits

A receipt is not a signature, proof of authorship, proof of delivery, proof that
the displayed contact key is correct, or proof that an endpoint was
uncompromised. It reports what the local implementation observed and did.

## Privacy rules

Receipts are local artifacts and must not be included in the public `.pqsend`
envelope. By default, they must avoid plaintext filenames, source or destination
paths, file contents, notes, private key material, and unnecessary identifiers.
Any optional identifying detail must be explicit and user-controlled.

Before implementation, receipt purpose, storage, retention, redaction,
exporting, and trust claims require updates to `SPEC.md` and `THREAT_MODEL.md`.
