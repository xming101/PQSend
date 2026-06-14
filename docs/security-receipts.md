# Security Receipts

Security receipts are local, human-readable command output for selected PQSend
operations. They make important choices and checks visible without asking users
to interpret cryptographic internals.

The v0.1 CLI prints receipts after successful `pack` and `open` operations.
They are not stored in or next to the `.pqsend` package.

Contact commands also print local contact names, canonical recipients, and
full or short fingerprints where needed. `contact fingerprint` displays all
required fields, and `contact verify` displays the canonical recipient and full
fingerprint before requesting exact confirmation. These values remain local
CLI output and are never embedded in `.pqsend` package metadata.

## Pack receipt

Successful `pack` output uses this wording:

```text
Encrypted locally: yes
Original filename hidden in package: yes
Recipient source: explicit recipient file
Backend: age v1 X25519
Post-quantum secure: no
Known leakage: package size, transfer timing, and outer package filename
```

Verified contact packing replaces the recipient-source line with:

```text
Recipient source: contact
Contact name: <local contact name>
Contact verification: verified
Short fingerprint: <display-only short fingerprint>
```

An explicit unverified override instead prints:

```text
Contact verification: unverified; explicit override used
```

The override affects only that command and does not change the contact store.

## Open receipt

Successful `open` output uses this wording:

```text
Decryption succeeded: yes
Integrity verified: yes
Original filename restored: yes
Output path: <output-directory>/<restored-filename>
Backend: age v1 X25519
Post-quantum secure: no
```

## Trust limits

A receipt is not a signature, proof of authorship, proof of delivery, proof that
the displayed contact key is correct, or proof that an endpoint was
uncompromised. Contact verification is not identity proof or proof of key
control; users must compare the full fingerprint through an independent
authenticated channel. It reports what the local implementation observed and
did.

## Privacy rules

Receipts are local command output and are not included in the public `.pqsend`
envelope. The `pack` receipt avoids plaintext filenames, source paths,
destination paths, file contents, private key material, and unnecessary
identifiers. The `open` receipt intentionally displays the selected output path,
which includes the restored filename, only after successful authenticated
decryption and validation. Users should treat terminal logs containing an open
receipt as plaintext metadata.

Contact names, canonical recipients, fingerprints, and verification status in
terminal output are also local plaintext metadata. Short fingerprints are
display-only and must not be used for verification or duplicate decisions.
No contact receipt field is embedded in the public envelope or encrypted
manifest.
