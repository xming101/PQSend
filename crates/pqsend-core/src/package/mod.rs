//! Strict v0.1 `.pqsend` package framing.

use thiserror::Error;

use crate::backend::age::{decrypt_with_identity, encrypt_to_recipient};
use crate::{AgeBackendError, AgeIdentity, AgeRecipient};

pub mod envelope;
mod single_file;

pub use envelope::PublicEnvelope;
pub use single_file::SingleFile;

/// The only supported package format version.
pub const FORMAT_VERSION_V1: u16 = 1;
/// The only supported package mode.
pub const MODE_SINGLE_FILE: u8 = 1;
/// The only supported encryption backend.
pub const BACKEND_AGE_V1_X25519: u8 = 1;
/// The fixed public envelope length.
pub const PUBLIC_ENVELOPE_LEN: usize = 20;
/// The maximum encoded filename length.
pub const MAX_FILENAME_BYTES: usize = 255;
/// The maximum file body length.
pub const MAX_FILE_BYTES: usize = 67_108_864;
/// The maximum fixed and filename metadata length inside the encrypted plaintext.
pub const MAX_INNER_METADATA_BYTES: usize = 309;
/// The maximum complete inner plaintext length.
pub const MAX_INNER_PLAINTEXT_BYTES: usize = 67_109_173;
/// The maximum binary age payload length.
pub const MAX_ENCRYPTED_PAYLOAD_BYTES: usize = 68_157_749;
/// The maximum complete `.pqsend` package length.
pub const MAX_PACKAGE_BYTES: usize = 68_157_769;

/// Redacted failures from v0.1 package creation and opening.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PackageError {
    /// The package does not contain a complete public envelope.
    #[error("package is shorter than the public envelope")]
    PackageTooShort,
    /// The public envelope magic is not canonical.
    #[error("invalid package magic")]
    InvalidMagic,
    /// The package version is not supported.
    #[error("unsupported package version")]
    UnsupportedVersion,
    /// The package mode is not supported.
    #[error("unsupported package mode")]
    UnsupportedMode,
    /// The package backend is not supported.
    #[error("unsupported package backend")]
    UnsupportedBackend,
    /// The encrypted payload length is zero.
    #[error("invalid encrypted payload length")]
    InvalidEncryptedPayloadLength,
    /// The encrypted payload exceeds the v0.1 limit.
    #[error("encrypted payload exceeds the package limit")]
    EncryptedPayloadTooLarge,
    /// The package length does not exactly match its public envelope.
    #[error("package length does not match its public envelope")]
    PackageLengthMismatch,
    /// The authenticated plaintext is shorter than the fixed inner header.
    #[error("inner plaintext is shorter than the fixed header")]
    InnerHeaderTooShort,
    /// The authenticated plaintext magic is not canonical.
    #[error("invalid inner plaintext magic")]
    InvalidInnerMagic,
    /// The authenticated and public versions differ.
    #[error("inner and public package versions differ")]
    InnerVersionMismatch,
    /// The authenticated and public modes differ.
    #[error("inner and public package modes differ")]
    InnerModeMismatch,
    /// The authenticated and public backends differ.
    #[error("inner and public package backends differ")]
    InnerBackendMismatch,
    /// The authenticated filename is invalid or unsafe.
    #[error("invalid or unsafe inner filename")]
    InvalidFilename,
    /// The authenticated file body exceeds the v0.1 limit.
    #[error("inner file body exceeds the package limit")]
    FileTooLarge,
    /// The authenticated plaintext exceeds the v0.1 limit.
    #[error("inner plaintext exceeds the package limit")]
    InnerPlaintextTooLarge,
    /// The authenticated plaintext lengths are impossible or non-canonical.
    #[error("inner plaintext length is invalid")]
    InvalidInnerLength,
    /// The authenticated file body does not match its encrypted SHA-256 value.
    #[error("inner file hash mismatch")]
    HashMismatch,
    /// The reviewed age backend rejected the operation.
    #[error(transparent)]
    Backend(#[from] AgeBackendError),
}

/// Creates canonical v0.1 `.pqsend` package bytes without filesystem access.
pub fn create_package(
    original_filename: &str,
    file_bytes: &[u8],
    recipient: &AgeRecipient,
) -> Result<Vec<u8>, PackageError> {
    let inner = single_file::encode(original_filename, file_bytes)?;
    let mut encrypted_payload = Vec::new();
    encrypt_to_recipient(recipient, &inner[..], &mut encrypted_payload)?;

    if encrypted_payload.is_empty() {
        return Err(PackageError::InvalidEncryptedPayloadLength);
    }
    if encrypted_payload.len() > MAX_ENCRYPTED_PAYLOAD_BYTES {
        return Err(PackageError::EncryptedPayloadTooLarge);
    }

    let envelope = PublicEnvelope::v1(encrypted_payload.len())?;
    let package_len = PUBLIC_ENVELOPE_LEN
        .checked_add(encrypted_payload.len())
        .ok_or(PackageError::PackageLengthMismatch)?;
    if package_len > MAX_PACKAGE_BYTES {
        return Err(PackageError::PackageLengthMismatch);
    }

    let mut package = Vec::with_capacity(package_len);
    package.extend_from_slice(&envelope.encode());
    package.extend_from_slice(&encrypted_payload);
    Ok(package)
}

/// Opens and fully validates canonical v0.1 `.pqsend` package bytes.
///
/// No filename or file contents are returned until age authentication and all
/// inner framing checks succeed.
pub fn open_package(package: &[u8], identity: &AgeIdentity) -> Result<SingleFile, PackageError> {
    let envelope = PublicEnvelope::decode(package)?;
    let encrypted_payload_len = usize::try_from(envelope.encrypted_payload_len())
        .map_err(|_| PackageError::EncryptedPayloadTooLarge)?;
    let expected_package_len = PUBLIC_ENVELOPE_LEN
        .checked_add(encrypted_payload_len)
        .ok_or(PackageError::PackageLengthMismatch)?;

    if package.len() != expected_package_len {
        return Err(PackageError::PackageLengthMismatch);
    }

    let inner = decrypt_with_identity(identity, &package[PUBLIC_ENVELOPE_LEN..])?;
    if inner.len() > MAX_INNER_PLAINTEXT_BYTES {
        return Err(PackageError::InnerPlaintextTooLarge);
    }

    single_file::decode(&inner, &envelope)
}
