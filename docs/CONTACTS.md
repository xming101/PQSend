# Contacts: Local Recipient Trust

> [!WARNING]
> PQSend is experimental, unaudited, X25519-only, not post-quantum-secure, and
> unstable before `v1.0.0`.

PQSend contacts belong to the Rust reference CLI's local recipient-trust
workflow. They are local names for recipient public keys, local trust records,
and a convenience for selecting a recipient when creating a package.

Contacts are reference CLI metadata. They are not part of the `.pqsend`
package format.

## What contacts are

Each contact maps one local convenience name, such as `alice`, to exactly one
canonical age X25519 recipient public key. A contact may also contain a local
verification binding for that exact recipient fingerprint.

Contacts help a local user:

- give a recipient public key a memorable local name
- record whether the full fingerprint for that exact key was compared
- deliberately select a recipient with `pack --to <contact>`
- block accidental use of an unverified contact by default

The contact name has meaning only to the local user. PQSend does not
authenticate it.

## What contacts are not

Contacts are not:

- proof of a person's or organization's identity
- a Web of Trust
- a certificate authority or cryptographic certificate
- an account system, social address book, or remote directory
- automatic key discovery
- embedded records in `.pqsend` packages

PQSend does not implement networking, QR exchange, remote contact lookup, or
automatic contact verification.

## Current recipient type

The current contact recipient type is one canonical age X25519 recipient.
Contacts are X25519-only. The current recipient type is not post-quantum-secure.

The contact workflow does not change package encryption behavior. After the CLI
resolves a contact, it passes only the parsed age X25519 recipient to the
package core.

## Verification model

The user must compare the full fingerprint through an independent
authenticated channel. That channel must give the user a sound reason to
believe they are communicating with the intended recipient and should be
independent from the channel used to obtain the recipient key.

The implemented `pqsend contact verify <name>` command displays the canonical
recipient and full fingerprint, then requires exact entry of the full
fingerprint. Successful verification stores a local binding to that exact
recipient fingerprint. It is not a separate trusted boolean that remains valid
for a different key.

Verification means only:

> The local user says they compared this exact full recipient fingerprint
> through an independent authenticated channel.

Verification does not prove:

- identity
- current or future control of the corresponding private key
- delivery or receipt of a package
- sender authorship or a signature
- endpoint, local-account, or contact-store security

If the stored recipient changes, its fingerprint changes and the previous
verification binding is invalid. The new recipient must be independently
compared and verified.

## Fingerprints

The full fingerprint is authoritative for verification and security decisions.
It is computed from the exact canonical age X25519 recipient:

```text
pqsend-contact-v1:hex(SHA-256(
  "pqsend-contact-fingerprint-v1\0age-x25519\0" || canonical_recipient
))
```

The short fingerprint is display-only. It must not be used for verification,
recipient comparison, duplicate detection, or any other security decision.

## Contact privacy and package boundary

Contact state must remain local to the reference CLI:

- contact names must not enter public package metadata
- contact fingerprints must not enter public package metadata
- contact names and fingerprints should not enter the encrypted internal
  manifest for v0.1
- contact verification state must not enter the package

The current reference CLI keeps contact names, recipient strings,
fingerprints, and verification state out of both the public envelope and the
encrypted internal manifest.

Local receipts may display contact context. A successful contact-backed pack
receipt displays the local contact alias and verification outcome, but omits
the recipient key and contact fingerprint. Explicit contact-command output may
display recipient keys and fingerprints, and a blocked unverified-contact
error displays the full fingerprint. Terminal logs and captured output are
therefore local plaintext metadata that users must protect.

Receipts are local CLI output and are not embedded in or transmitted with a
`.pqsend` package.

## Unverified contacts

The implemented reference CLI blocks `pack --to <contact>` when the selected
contact is unverified.

The implemented `--allow-unverified` option is an explicit override for one
pack operation only. It reports the override in local output and does not
change the contact's stored verification state. A later pack to the same
unverified contact is blocked again unless that operation also uses the
override.

## Contact-store risks

The contact store is local plaintext state. Local account compromise can
modify contacts, and contact-store compromise can replace recipient keys and
their matching verification bindings. This can cause future packages selected
by contact name to be encrypted to an attacker-controlled key.

Verification is only as strong as both:

- the local contact store and account remaining trustworthy
- the user's independent authenticated fingerprint-comparison process

On Unix, the reference CLI enforces private modes for the config directory and
contact-store file. Windows does not currently enforce equivalent ACL privacy.
These checks do not protect against an attacker who controls the local account.

## Store compatibility

The contact-store format is experimental and separate from the `.pqsend`
package format. The current store format is `experimental-v1`, and there is no
pre-`v1.0.0` compatibility promise.

The reference CLI rejects old, unknown, malformed, or incompatible stores
rather than automatically migrating trust decisions. Old stores may require
contacts to be explicitly re-imported and independently re-verified.

The current store accepts one canonical age X25519 recipient per contact.
Contact names are unique ASCII-case-insensitively, and duplicate canonical
recipients are rejected.

## Example workflow

The commands in this workflow are implemented by the current Rust reference
CLI. First initialize the local contact store if needed:

```sh
pqsend init
```

Add a local contact from a file containing exactly one age X25519 recipient:

```sh
pqsend contact add alice alice-recipient.txt
```

Show the authoritative full fingerprint and the display-only short
fingerprint:

```sh
pqsend contact fingerprint alice
```

Compare the full fingerprint through an independent authenticated channel,
then verify the exact full fingerprint interactively:

```sh
pqsend contact verify alice
```

Create one package for the verified contact:

```sh
pqsend pack report.pdf --to alice --out report.pqsend
```

Contact replacement, Web of Trust, QR exchange, networking, and automatic key
discovery are not implemented.

## Related documents

- [Package format](FORMAT.md)
- [Security model](SECURITY-MODEL.md)
- [Threat model](THREAT-MODEL.md)
- [Security receipts](RECEIPTS.md)
