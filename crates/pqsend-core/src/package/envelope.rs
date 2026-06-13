//! Canonical public-envelope encoding and parsing.

use super::{
    PackageError, BACKEND_AGE_V1_X25519, FORMAT_VERSION_V1, MAX_ENCRYPTED_PAYLOAD_BYTES,
    MODE_SINGLE_FILE, PUBLIC_ENVELOPE_LEN,
};

/// Canonical v0.1 public-envelope magic.
pub const MAGIC: [u8; 8] = [0x89, b'P', b'Q', b'S', b'E', b'N', b'D', b'\n'];

/// A validated v0.1 public envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicEnvelope {
    version: u16,
    mode: u8,
    backend: u8,
    encrypted_payload_len: u64,
}

impl PublicEnvelope {
    /// Constructs the only supported v0.1 envelope.
    pub fn v1(encrypted_payload_len: usize) -> Result<Self, PackageError> {
        if encrypted_payload_len == 0 {
            return Err(PackageError::InvalidEncryptedPayloadLength);
        }
        if encrypted_payload_len > MAX_ENCRYPTED_PAYLOAD_BYTES {
            return Err(PackageError::EncryptedPayloadTooLarge);
        }

        let encrypted_payload_len = u64::try_from(encrypted_payload_len)
            .map_err(|_| PackageError::EncryptedPayloadTooLarge)?;
        Ok(Self {
            version: FORMAT_VERSION_V1,
            mode: MODE_SINGLE_FILE,
            backend: BACKEND_AGE_V1_X25519,
            encrypted_payload_len,
        })
    }

    /// Parses and validates the first fixed-width public envelope.
    pub fn decode(bytes: &[u8]) -> Result<Self, PackageError> {
        if bytes.len() < PUBLIC_ENVELOPE_LEN {
            return Err(PackageError::PackageTooShort);
        }
        if bytes[..8] != MAGIC {
            return Err(PackageError::InvalidMagic);
        }

        let version = u16::from_be_bytes([bytes[8], bytes[9]]);
        if version != FORMAT_VERSION_V1 {
            return Err(PackageError::UnsupportedVersion);
        }

        let mode = bytes[10];
        if mode != MODE_SINGLE_FILE {
            return Err(PackageError::UnsupportedMode);
        }

        let backend = bytes[11];
        if backend != BACKEND_AGE_V1_X25519 {
            return Err(PackageError::UnsupportedBackend);
        }

        let encrypted_payload_len = u64::from_be_bytes([
            bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19],
        ]);
        if encrypted_payload_len == 0 {
            return Err(PackageError::InvalidEncryptedPayloadLength);
        }
        let maximum = u64::try_from(MAX_ENCRYPTED_PAYLOAD_BYTES)
            .map_err(|_| PackageError::EncryptedPayloadTooLarge)?;
        if encrypted_payload_len > maximum {
            return Err(PackageError::EncryptedPayloadTooLarge);
        }

        Ok(Self {
            version,
            mode,
            backend,
            encrypted_payload_len,
        })
    }

    /// Encodes the validated envelope as exactly 20 canonical bytes.
    pub fn encode(self) -> [u8; PUBLIC_ENVELOPE_LEN] {
        let mut bytes = [0_u8; PUBLIC_ENVELOPE_LEN];
        bytes[..8].copy_from_slice(&MAGIC);
        bytes[8..10].copy_from_slice(&self.version.to_be_bytes());
        bytes[10] = self.mode;
        bytes[11] = self.backend;
        bytes[12..20].copy_from_slice(&self.encrypted_payload_len.to_be_bytes());
        bytes
    }

    /// Returns the validated format version.
    pub fn version(self) -> u16 {
        self.version
    }

    /// Returns the validated package mode.
    pub fn mode(self) -> u8 {
        self.mode
    }

    /// Returns the validated backend identifier.
    pub fn backend(self) -> u8 {
        self.backend
    }

    /// Returns the encrypted payload length.
    pub fn encrypted_payload_len(self) -> u64 {
        self.encrypted_payload_len
    }
}
