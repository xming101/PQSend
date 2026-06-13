//! Core library for PQSend.
//!
//! Contact storage is experimental. Package handling and cryptographic
//! behavior are intentionally not implemented.

mod contact;

pub use contact::{
    Contact, ContactBook, ContactError, InitResult, VerifyResult, CONTACTS_FILE_NAME,
    CONTACT_STORE_FORMAT,
};

/// The current package specification status.
pub const PACKAGE_SPEC_STATUS: &str = "placeholder-v0";
