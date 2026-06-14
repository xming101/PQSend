# Contacts: Local Recipient Trust Store

PQSend contacts are a local recipient trust store. They are not a social
address book, directory service, identity system, or source of package
metadata. The store helps a local user reduce the risk of encrypting to the
wrong recipient key.

Each contact maps one local convenience alias, such as `alice`, to one
canonical age X25519 recipient. The alias has meaning only to the local user.
It is not authenticated by PQSend and does not establish the recipient's
real-world identity.

The current contact backend is X25519-only and is not post-quantum-secure.

## Package boundary

Contacts are resolved only by the CLI before package creation. For
`pack --to <contact>`, the CLI loads and validates the contact, then supplies
only the parsed age X25519 recipient to the package core.

Contact aliases, canonical recipient strings, fingerprints, and verification
status may appear in local terminal output and local security receipts. They
must not appear in the public envelope or encrypted metadata of a `.pqsend`
package. Security receipts are command output; they are not embedded into the
package.

## Fingerprints and verification

A contact fingerprint is a local aid for comparing one canonical recipient
key. The full fingerprint is computed from the exact canonical age X25519
recipient and is authoritative for verification:

```text
pqsend-contact-v1:hex(SHA-256(
  "pqsend-contact-fingerprint-v1\0age-x25519\0" || canonical_recipient
))
```

The short fingerprint is only a compact display aid. It must not be used to
verify a contact or make duplicate-recipient decisions.

`pqsend contact verify <name>` displays the canonical recipient and full
fingerprint, then requires an exact full-fingerprint confirmation.
Verification records a local binding to that exact canonical recipient key,
not a separate trusted boolean. Changing the recipient key changes the full
fingerprint and invalidates the previous verification binding. A new key must
be independently compared and verified.

Before confirming verification, the local user must compare the full
fingerprint through an independent authenticated channel. The comparison
channel must be independent from the channel used to obtain the recipient key
and must give the user a sound reason to believe they are communicating with
the intended recipient.

In PQSend, verification means only:

> The local user says they compared the full fingerprint through an
> independent authenticated channel.

Verification is not:

- proof of the contact's real-world identity
- proof of sender authorship or a signature
- proof of delivery
- proof that the recipient currently controls the private key
- proof that the recipient will control or protect the key forever
- proof that either endpoint or local account is uncompromised

Unverified contacts provide no recipient-key verification assurance.
`pack --to <contact>` blocks them by default. The explicit
`--allow-unverified` option bypasses that local policy for one command, reports
the override in local output, and does not mark the contact as verified.

## Local-store risks

The contact store is local plaintext state. An attacker who compromises the
local account or contact store can replace recipient keys and their matching
verification bindings, causing future contact-selected packages to be
encrypted to an attacker-controlled key. On Unix, PQSend enforces private
config-directory and store-file modes. Windows does not currently enforce
equivalent ACL privacy. These checks and recipient-bound fingerprints do not
protect against an attacker controlling the local account.

Terminal output and receipts containing contact aliases, canonical recipients,
fingerprints, or verification status are also local plaintext metadata. Users
must protect terminal logs and other local records according to their privacy
needs.

## Experimental format and compatibility

The existing alpha contact-store format is `experimental-v1` and is unstable.
There is no pre-`v1.0.0` compatibility promise. PQSend rejects old or unknown
incompatible store formats rather than automatically migrating trust
decisions. Incompatible stores may require contacts to be explicitly
re-imported and independently re-verified.

The current store accepts one canonical age X25519 recipient per contact.
Contact aliases are unique ASCII-case-insensitively, and duplicate canonical
recipients are rejected. See [the draft specification](../SPEC.md) and
[threat model](THREAT-MODEL.md) for the normative implemented behavior and
broader security limitations.
