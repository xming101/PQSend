//! Core library for PQSend.
//!
//! Contact storage and the narrow age backend adapter are experimental.
//! `.pqsend` package handling is intentionally not implemented.

#![forbid(unsafe_code)]

pub mod backend;
mod contact;

pub use backend::age::{
    decrypt_with_identity, encrypt_to_recipient, AgeBackend, AgeBackendError, AgeIdentity,
    AgeRecipient,
};
pub use contact::{
    Contact, ContactBook, ContactError, InitResult, VerifyResult, CONTACTS_FILE_NAME,
    CONTACT_STORE_FORMAT,
};

/// The current package specification status.
pub const PACKAGE_SPEC_STATUS: &str = "placeholder-v0";
