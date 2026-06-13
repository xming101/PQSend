# Security Receipts

Security receipts are a possible future user-facing record of local PQSend
operations. They are a design concept only and are not implemented.

A receipt might help a user answer questions such as:

- which locally verified contact was selected for a package operation?
- which package revision was processed?
- which safety checks completed before extraction?

Receipts must not be treated as signatures, proof of delivery, proof of
authorship, or proof that an endpoint was uncompromised. They must avoid
exposing plaintext filenames, sensitive paths, key material, or unnecessary
identifiers.

Before implementation, the receipt purpose, storage, retention, metadata, and
trust claims require updates to `SPEC.md` and `THREAT_MODEL.md`.
