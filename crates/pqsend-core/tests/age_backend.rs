use std::io::{self, Read, Write};

use age::secrecy::ExposeSecret;
use base64::{engine::general_purpose::STANDARD, Engine};
use pqsend_core::{
    decrypt_with_identity, encrypt_to_recipient, AgeBackend, AgeBackendError, AgeIdentity,
    AgeRecipient,
};

fn keypair() -> (AgeIdentity, AgeRecipient) {
    let identity = age::x25519::Identity::generate();
    let recipient = identity
        .to_public()
        .to_string()
        .parse()
        .expect("parse generated test recipient");
    let identity = identity.to_string();
    let identity = identity
        .expose_secret()
        .parse()
        .expect("parse generated test identity");

    (identity, recipient)
}

fn encrypt(recipient: &AgeRecipient, plaintext: &[u8]) -> Vec<u8> {
    let mut ciphertext = Vec::new();
    encrypt_to_recipient(recipient, plaintext, &mut ciphertext).expect("encrypt test plaintext");
    ciphertext
}

fn decrypt(identity: &AgeIdentity, ciphertext: &[u8]) -> Result<Vec<u8>, AgeBackendError> {
    decrypt_with_identity(identity, ciphertext)
}

#[test]
fn round_trip_encryption_and_decryption() {
    let (identity, recipient) = keypair();
    let plaintext = b"PQSend age backend round trip";

    let ciphertext = encrypt(&recipient, plaintext);
    let decrypted = decrypt(&identity, &ciphertext).expect("decrypt test ciphertext");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn round_trip_payload_larger_than_64_kib() {
    let (identity, recipient) = keypair();
    let plaintext = (0..(128 * 1024 + 37))
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();

    let ciphertext = encrypt(&recipient, &plaintext);
    let decrypted = decrypt(&identity, &ciphertext).expect("decrypt large test ciphertext");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn wrong_identity_fails_without_returning_plaintext() {
    let (_identity, recipient) = keypair();
    let (wrong_identity, _wrong_recipient) = keypair();
    let ciphertext = encrypt(&recipient, b"must remain secret");

    let error = decrypt_with_identity(&wrong_identity, &ciphertext[..])
        .expect_err("wrong identity must fail");

    assert_eq!(error, AgeBackendError::NoMatchingIdentity);
}

#[test]
fn header_tampering_fails_without_returning_plaintext() {
    let (identity, recipient) = keypair();
    let mut ciphertext = encrypt(&recipient, b"must remain secret");
    let mac_start = ciphertext
        .windows(4)
        .position(|window| window == b"--- ")
        .expect("age header MAC marker")
        + 4;
    ciphertext[mac_start] = if ciphertext[mac_start] == b'A' {
        b'B'
    } else {
        b'A'
    };
    let error =
        decrypt_with_identity(&identity, &ciphertext[..]).expect_err("tampered header must fail");

    assert_eq!(error, AgeBackendError::InvalidCiphertext);
}

#[test]
fn payload_tampering_fails_without_returning_plaintext() {
    let (identity, recipient) = keypair();
    let plaintext = vec![42; 128 * 1024 + 37];
    let mut ciphertext = encrypt(&recipient, &plaintext);
    let last = ciphertext.last_mut().expect("ciphertext payload byte");
    *last ^= 1;

    let error =
        decrypt_with_identity(&identity, &ciphertext[..]).expect_err("tampered payload must fail");

    assert_eq!(error, AgeBackendError::InvalidCiphertext);
}

#[test]
fn truncation_fails_without_returning_plaintext() {
    let (identity, recipient) = keypair();
    let mut ciphertext = encrypt(&recipient, b"must remain secret");
    ciphertext.pop();

    let error = decrypt_with_identity(&identity, &ciphertext[..])
        .expect_err("truncated ciphertext must fail");

    assert_eq!(error, AgeBackendError::InvalidCiphertext);
}

#[test]
fn multiple_recipient_ciphertext_is_rejected() {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();
    let other_recipient = age::x25519::Identity::generate().to_public();
    let adapter_identity = identity.to_string();
    let adapter_identity = adapter_identity
        .expose_secret()
        .parse::<AgeIdentity>()
        .expect("parse generated test identity");
    let mut ciphertext = Vec::new();
    let encryptor = age::Encryptor::with_recipients(
        [&recipient, &other_recipient]
            .into_iter()
            .map(|recipient| recipient as &dyn age::Recipient),
    )
    .expect("encrypt to multiple test recipients");
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .expect("wrap test ciphertext");
    writer
        .write_all(b"must remain single recipient")
        .expect("write test plaintext");
    writer.finish().expect("finish test ciphertext");

    let error = decrypt_with_identity(&adapter_identity, &ciphertext[..])
        .expect_err("multiple-recipient ciphertext must fail");

    assert_eq!(error, AgeBackendError::InvalidCiphertext);
}

#[test]
fn passphrase_ciphertext_is_rejected() {
    let (identity, _recipient) = keypair();
    let encryptor = age::Encryptor::with_user_passphrase(age::secrecy::SecretString::from(
        "test passphrase".to_owned(),
    ));
    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .expect("wrap passphrase ciphertext");
    writer
        .write_all(b"unsupported passphrase mode")
        .expect("write test plaintext");
    writer.finish().expect("finish passphrase ciphertext");

    let error = decrypt_with_identity(&identity, &ciphertext[..])
        .expect_err("passphrase ciphertext must fail");

    assert_eq!(error, AgeBackendError::InvalidCiphertext);
}

#[test]
fn ascii_armored_ciphertext_is_rejected() {
    let (identity, recipient) = keypair();
    let ciphertext = encrypt(&recipient, b"unsupported ASCII armor");
    let encoded = STANDARD.encode(ciphertext);
    let mut armored = String::from("-----BEGIN AGE ENCRYPTED FILE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        armored.push_str(std::str::from_utf8(line).expect("Base64 output is UTF-8"));
        armored.push('\n');
    }
    armored.push_str("-----END AGE ENCRYPTED FILE-----\n");

    let error = decrypt_with_identity(&identity, armored.as_bytes())
        .expect_err("ASCII-armored ciphertext must fail");

    assert_eq!(error, AgeBackendError::InvalidCiphertext);
}

#[test]
fn unsupported_recipient_key_fails_closed() {
    let error = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN"
        .parse::<AgeRecipient>()
        .expect_err("SSH recipient must be rejected");

    assert_eq!(error, AgeBackendError::InvalidRecipientKey);
}

#[test]
fn unsupported_identity_key_fails_closed() {
    let error = "AGE-PLUGIN-FOOBAR-1QVHULF"
        .parse::<AgeIdentity>()
        .expect_err("plugin identity must be rejected");

    assert_eq!(error, AgeBackendError::InvalidIdentityKey);
}

#[test]
fn encrypted_output_is_not_plaintext() {
    let (_identity, recipient) = keypair();
    let plaintext = b"plaintext must not be the ciphertext";

    let ciphertext = encrypt(&recipient, plaintext);

    assert_ne!(ciphertext, plaintext);
    assert!(!ciphertext
        .windows(plaintext.len())
        .any(|window| window == plaintext));
}

#[test]
fn encryption_finishes_empty_payload_and_produces_decryptable_output() {
    let (identity, recipient) = keypair();
    let mut ciphertext = Vec::new();

    AgeBackend::encrypt_to_recipient(&recipient, io::empty(), &mut ciphertext)
        .expect("encrypt empty payload");
    let plaintext = AgeBackend::decrypt_with_identity(&identity, &ciphertext[..])
        .expect("decrypt finished empty payload");

    assert!(plaintext.is_empty());
}

#[test]
fn errors_and_identity_debug_output_are_redacted() {
    let generated = age::x25519::Identity::generate();
    let secret = generated.to_string();
    let identity = secret
        .expose_secret()
        .parse::<AgeIdentity>()
        .expect("parse generated test identity");
    let error = "not an identity"
        .parse::<AgeIdentity>()
        .expect_err("invalid identity must fail");

    assert!(!format!("{identity:?}").contains(secret.expose_secret()));
    assert!(!error.to_string().contains("not an identity"));
    assert!(!format!("{error:?}").contains("not an identity"));
}

#[test]
fn input_io_errors_are_redacted_and_distinct() {
    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("sensitive reader detail"))
        }
    }

    let (_identity, recipient) = keypair();
    let mut ciphertext = Vec::new();
    let error = encrypt_to_recipient(&recipient, FailingReader, &mut ciphertext)
        .expect_err("input I/O error must fail");

    assert_eq!(error, AgeBackendError::Io);
    assert!(!error.to_string().contains("sensitive reader detail"));
    assert!(!format!("{error:?}").contains("sensitive reader detail"));
}
