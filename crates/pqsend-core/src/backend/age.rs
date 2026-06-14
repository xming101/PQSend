//! Binary age v1 encryption for exactly one X25519 recipient.

use std::fmt;
use std::io::{self, Read, Write};
use std::iter;
use std::str::FromStr;

use age::{DecryptError, Decryptor, Encryptor};
use age_core::format::{FileKey, Stanza};
use thiserror::Error;

const X25519_STANZA_TAG: &str = "X25519";
const GREASE_STANZA_SUFFIX: &str = "-grease";

/// An age X25519 recipient accepted by the PQSend backend adapter.
#[derive(Clone, Eq, PartialEq)]
pub struct AgeRecipient(age::x25519::Recipient);

impl fmt::Debug for AgeRecipient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AgeRecipient")
    }
}

impl fmt::Display for AgeRecipient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for AgeRecipient {
    type Err = AgeBackendError;

    fn from_str(recipient: &str) -> Result<Self, Self::Err> {
        recipient
            .parse::<age::x25519::Recipient>()
            .map(Self)
            .map_err(|_| AgeBackendError::InvalidRecipientKey)
    }
}

/// An age X25519 identity accepted by the PQSend backend adapter.
pub struct AgeIdentity(age::x25519::Identity);

impl fmt::Debug for AgeIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AgeIdentity([REDACTED])")
    }
}

impl FromStr for AgeIdentity {
    type Err = AgeBackendError;

    fn from_str(identity: &str) -> Result<Self, Self::Err> {
        identity
            .parse::<age::x25519::Identity>()
            .map(Self)
            .map_err(|_| AgeBackendError::InvalidIdentityKey)
    }
}

/// Redacted failures from the narrow age backend adapter.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AgeBackendError {
    /// The supplied recipient is not a valid age X25519 recipient.
    #[error("invalid age X25519 recipient key")]
    InvalidRecipientKey,
    /// The supplied identity is not a valid age X25519 identity.
    #[error("invalid age X25519 identity key")]
    InvalidIdentityKey,
    /// The supplied identity cannot decrypt the ciphertext.
    #[error("no matching age X25519 identity")]
    NoMatchingIdentity,
    /// The age encryptor rejected the single X25519 recipient.
    #[error("age encryption failed")]
    EncryptionFailed,
    /// The ciphertext is malformed, truncated, or failed authentication.
    #[error("invalid or tampered age ciphertext")]
    InvalidCiphertext,
    /// An input or output operation failed.
    #[error("I/O error while processing age data")]
    Io,
}

/// Stateless entry point for the narrow age backend adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct AgeBackend;

impl AgeBackend {
    /// Encrypts a byte stream to exactly one X25519 recipient as binary age v1.
    pub fn encrypt_to_recipient<R: Read, W: Write>(
        recipient: &AgeRecipient,
        plaintext: R,
        ciphertext: W,
    ) -> Result<(), AgeBackendError> {
        encrypt_to_recipient(recipient, plaintext, ciphertext)
    }

    /// Decrypts binary age v1 data containing exactly one X25519 recipient stanza.
    ///
    /// Plaintext is returned only after the complete ciphertext is authenticated.
    pub fn decrypt_with_identity<R: Read>(
        identity: &AgeIdentity,
        ciphertext: R,
    ) -> Result<Vec<u8>, AgeBackendError> {
        decrypt_with_identity(identity, ciphertext)
    }
}

/// Encrypts a byte stream to exactly one X25519 recipient as binary age v1.
pub fn encrypt_to_recipient<R: Read, W: Write>(
    recipient: &AgeRecipient,
    mut plaintext: R,
    ciphertext: W,
) -> Result<(), AgeBackendError> {
    let encryptor = Encryptor::with_recipients(iter::once(&recipient.0 as &dyn age::Recipient))
        .map_err(|_| AgeBackendError::EncryptionFailed)?;
    let mut writer = encryptor
        .wrap_output(ciphertext)
        .map_err(|_| AgeBackendError::Io)?;

    io::copy(&mut plaintext, &mut writer).map_err(|_| AgeBackendError::Io)?;
    writer.finish().map_err(|_| AgeBackendError::Io)?;

    Ok(())
}

/// Decrypts binary age v1 data containing exactly one X25519 recipient stanza.
///
/// Plaintext is returned only after the complete ciphertext is authenticated.
pub fn decrypt_with_identity<R: Read>(
    identity: &AgeIdentity,
    ciphertext: R,
) -> Result<Vec<u8>, AgeBackendError> {
    let decryptor = Decryptor::new(ciphertext).map_err(classify_decrypt_error)?;
    let restricted_identity = SingleX25519Identity(&identity.0);
    let mut reader = decryptor
        .decrypt(iter::once(&restricted_identity as &dyn age::Identity))
        .map_err(classify_decrypt_error)?;

    let mut authenticated_plaintext = Vec::new();
    reader
        .read_to_end(&mut authenticated_plaintext)
        .map_err(classify_ciphertext_io_error)?;

    Ok(authenticated_plaintext)
}

struct SingleX25519Identity<'a>(&'a age::x25519::Identity);

impl age::Identity for SingleX25519Identity<'_> {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        age::Identity::unwrap_stanza(self.0, stanza)
    }

    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Option<Result<FileKey, DecryptError>> {
        // Age v1 adds GREASE stanzas; every other non-X25519 tag is an unsupported mode.
        let x25519_stanzas = stanzas
            .iter()
            .filter(|stanza| stanza.tag == X25519_STANZA_TAG)
            .count();
        let has_unsupported_stanza = stanzas.iter().any(|stanza| {
            stanza.tag != X25519_STANZA_TAG && !stanza.tag.ends_with(GREASE_STANZA_SUFFIX)
        });

        if x25519_stanzas != 1 || has_unsupported_stanza {
            return Some(Err(DecryptError::InvalidHeader));
        }

        age::Identity::unwrap_stanzas(self.0, stanzas)
    }
}

fn classify_decrypt_error(error: DecryptError) -> AgeBackendError {
    match error {
        DecryptError::NoMatchingKeys => AgeBackendError::NoMatchingIdentity,
        DecryptError::Io(error) => classify_ciphertext_io_error(error),
        DecryptError::DecryptionFailed
        | DecryptError::ExcessiveWork { .. }
        | DecryptError::InvalidHeader
        | DecryptError::InvalidMac
        | DecryptError::KeyDecryptionFailed
        | DecryptError::UnknownFormat => AgeBackendError::InvalidCiphertext,
    }
}

fn classify_ciphertext_io_error(error: io::Error) -> AgeBackendError {
    match error.kind() {
        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => {
            AgeBackendError::InvalidCiphertext
        }
        _ => AgeBackendError::Io,
    }
}
