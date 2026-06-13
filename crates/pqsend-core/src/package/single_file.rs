//! Canonical encrypted single-file plaintext encoding and parsing.

use sha2::{Digest, Sha256};

use super::{
    PackageError, PublicEnvelope, BACKEND_AGE_V1_X25519, FORMAT_VERSION_V1, MAX_FILENAME_BYTES,
    MAX_FILE_BYTES, MAX_INNER_METADATA_BYTES, MAX_INNER_PLAINTEXT_BYTES, MODE_SINGLE_FILE,
};

/// Canonical v0.1 inner-plaintext magic.
pub const INNER_MAGIC: [u8; 8] = *b"PQSINNER";
/// The fixed inner header length before the filename and file body.
pub const INNER_HEADER_LEN: usize = 54;

/// A fully authenticated and validated single-file package result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SingleFile {
    /// The restored safe filename.
    pub filename: String,
    /// The exact restored file bytes.
    pub file_bytes: Vec<u8>,
    /// The authenticated file size.
    pub file_size: u64,
    /// The authenticated SHA-256 hash of `file_bytes`.
    pub sha256: [u8; 32],
}

/// Encodes a canonical v0.1 single-file inner plaintext.
pub(super) fn encode(original_filename: &str, file_bytes: &[u8]) -> Result<Vec<u8>, PackageError> {
    validate_filename(original_filename)?;
    let filename_bytes = original_filename.as_bytes();
    if filename_bytes.len() > MAX_FILENAME_BYTES {
        return Err(PackageError::InvalidFilename);
    }
    if file_bytes.len() > MAX_FILE_BYTES {
        return Err(PackageError::FileTooLarge);
    }

    let metadata_len = INNER_HEADER_LEN
        .checked_add(filename_bytes.len())
        .ok_or(PackageError::InnerPlaintextTooLarge)?;
    if metadata_len > MAX_INNER_METADATA_BYTES {
        return Err(PackageError::InnerPlaintextTooLarge);
    }
    let inner_len = metadata_len
        .checked_add(file_bytes.len())
        .ok_or(PackageError::InnerPlaintextTooLarge)?;
    if inner_len > MAX_INNER_PLAINTEXT_BYTES {
        return Err(PackageError::InnerPlaintextTooLarge);
    }

    let filename_len =
        u16::try_from(filename_bytes.len()).map_err(|_| PackageError::InvalidFilename)?;
    let file_size = u64::try_from(file_bytes.len()).map_err(|_| PackageError::FileTooLarge)?;
    let hash: [u8; 32] = Sha256::digest(file_bytes).into();

    let mut inner = Vec::with_capacity(inner_len);
    inner.extend_from_slice(&INNER_MAGIC);
    inner.extend_from_slice(&FORMAT_VERSION_V1.to_be_bytes());
    inner.push(MODE_SINGLE_FILE);
    inner.push(BACKEND_AGE_V1_X25519);
    inner.extend_from_slice(&filename_len.to_be_bytes());
    inner.extend_from_slice(&file_size.to_be_bytes());
    inner.extend_from_slice(&hash);
    inner.extend_from_slice(filename_bytes);
    inner.extend_from_slice(file_bytes);
    Ok(inner)
}

/// Parses and validates a complete authenticated v0.1 single-file plaintext.
pub(super) fn decode(inner: &[u8], envelope: &PublicEnvelope) -> Result<SingleFile, PackageError> {
    if inner.len() > MAX_INNER_PLAINTEXT_BYTES {
        return Err(PackageError::InnerPlaintextTooLarge);
    }
    if inner.len() < INNER_HEADER_LEN {
        return Err(PackageError::InnerHeaderTooShort);
    }
    if inner[..8] != INNER_MAGIC {
        return Err(PackageError::InvalidInnerMagic);
    }

    let version = u16::from_be_bytes([inner[8], inner[9]]);
    if version != envelope.version() {
        return Err(PackageError::InnerVersionMismatch);
    }
    let mode = inner[10];
    if mode != envelope.mode() {
        return Err(PackageError::InnerModeMismatch);
    }
    let backend = inner[11];
    if backend != envelope.backend() {
        return Err(PackageError::InnerBackendMismatch);
    }

    let filename_len = usize::from(u16::from_be_bytes([inner[12], inner[13]]));
    if filename_len == 0 || filename_len > MAX_FILENAME_BYTES {
        return Err(PackageError::InvalidFilename);
    }

    let file_size = u64::from_be_bytes([
        inner[14], inner[15], inner[16], inner[17], inner[18], inner[19], inner[20], inner[21],
    ]);
    let maximum_file_size =
        u64::try_from(MAX_FILE_BYTES).map_err(|_| PackageError::FileTooLarge)?;
    if file_size > maximum_file_size {
        return Err(PackageError::FileTooLarge);
    }
    let file_len = usize::try_from(file_size).map_err(|_| PackageError::FileTooLarge)?;

    let filename_end = INNER_HEADER_LEN
        .checked_add(filename_len)
        .ok_or(PackageError::InvalidInnerLength)?;
    let body_end = filename_end
        .checked_add(file_len)
        .ok_or(PackageError::InvalidInnerLength)?;
    if body_end != inner.len() {
        return Err(PackageError::InvalidInnerLength);
    }

    let filename = std::str::from_utf8(&inner[INNER_HEADER_LEN..filename_end])
        .map_err(|_| PackageError::InvalidFilename)?;
    validate_filename(filename)?;

    let mut expected_hash = [0_u8; 32];
    expected_hash.copy_from_slice(&inner[22..54]);
    let file_bytes = &inner[filename_end..body_end];
    let actual_hash: [u8; 32] = Sha256::digest(file_bytes).into();
    if actual_hash != expected_hash {
        return Err(PackageError::HashMismatch);
    }

    Ok(SingleFile {
        filename: filename.to_owned(),
        file_bytes: file_bytes.to_vec(),
        file_size,
        sha256: expected_hash,
    })
}

/// Rejects unsafe filenames rather than sanitizing them.
fn validate_filename(filename: &str) -> Result<(), PackageError> {
    let bytes = filename.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_FILENAME_BYTES || filename == "." || filename == ".." {
        return Err(PackageError::InvalidFilename);
    }

    if bytes.iter().any(|byte| {
        matches!(
            byte,
            0x00..=0x1f | 0x7f | b'/' | b'\\' | b'<' | b'>' | b':' | b'"' | b'|' | b'?' | b'*'
        )
    }) {
        return Err(PackageError::InvalidFilename);
    }

    if bytes.last().is_some_and(|byte| matches!(byte, b'.' | b' ')) {
        return Err(PackageError::InvalidFilename);
    }

    let device_stem = filename.split('.').next().unwrap_or(filename);
    if is_reserved_windows_device_name(device_stem) {
        return Err(PackageError::InvalidFilename);
    }

    Ok(())
}

fn is_reserved_windows_device_name(name: &str) -> bool {
    if name.eq_ignore_ascii_case("CON")
        || name.eq_ignore_ascii_case("PRN")
        || name.eq_ignore_ascii_case("AUX")
        || name.eq_ignore_ascii_case("NUL")
    {
        return true;
    }

    let Some(prefix) = name.get(..3) else {
        return false;
    };
    let Some(suffix) = name.get(3..) else {
        return false;
    };

    (prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT"))
        && matches!(
            suffix,
            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
        )
}
