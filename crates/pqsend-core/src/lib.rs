//! Core library for PQSend.
//!
//! Contact storage, the narrow age backend adapter, and strict v0.1 package
//! framing are experimental.

#![forbid(unsafe_code)]

pub mod backend;
mod contact;
pub mod package;

pub use backend::age::{
    decrypt_with_identity, encrypt_to_recipient, AgeBackend, AgeBackendError, AgeIdentity,
    AgeRecipient,
};
pub use contact::{
    full_fingerprint, short_fingerprint, Contact, ContactBook, ContactError, InitResult,
    VerifyResult, CONTACTS_FILE_NAME, CONTACT_FINGERPRINT_PREFIX, CONTACT_RECIPIENT_TYPE,
    CONTACT_STORE_FORMAT,
};
pub use package::{
    create_package, open_package, PackageError, PublicEnvelope, SingleFile, BACKEND_AGE_V1_X25519,
    FORMAT_VERSION_V1, MAX_ENCRYPTED_PAYLOAD_BYTES, MAX_FILENAME_BYTES, MAX_FILE_BYTES,
    MAX_INNER_METADATA_BYTES, MAX_INNER_PLAINTEXT_BYTES, MAX_PACKAGE_BYTES, MODE_SINGLE_FILE,
    PUBLIC_ENVELOPE_LEN,
};

/// The current package specification status.
pub const PACKAGE_SPEC_STATUS: &str = "experimental-v0.1";
