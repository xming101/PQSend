use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::{Builder, NamedTempFile};
use thiserror::Error;

use crate::AgeRecipient;

pub const CONTACTS_FILE_NAME: &str = "contacts.toml";
pub const CONTACT_STORE_FORMAT: &str = "experimental-v1";
pub const CONTACT_RECIPIENT_TYPE: &str = "age-x25519";
pub const CONTACT_FINGERPRINT_PREFIX: &str = "pqsend-contact-v1:";

const FINGERPRINT_DOMAIN: &[u8] = b"pqsend-contact-fingerprint-v1\0age-x25519\0";
const MAX_RECIPIENT_FILE_BYTES: usize = 16 * 1024;
const MAX_CONTACT_STORE_BYTES: usize = 1024 * 1024;
const MAX_CONTACTS: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Contact {
    name: String,
    recipient_type: &'static str,
    recipient: String,
    full_fingerprint: String,
    short_fingerprint: String,
    age_recipient: AgeRecipient,
    verified_fingerprint: Option<String>,
}

impl Contact {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn recipient_type(&self) -> &'static str {
        self.recipient_type
    }

    pub fn recipient(&self) -> &str {
        &self.recipient
    }

    pub fn full_fingerprint(&self) -> &str {
        &self.full_fingerprint
    }

    pub fn short_fingerprint(&self) -> &str {
        &self.short_fingerprint
    }

    pub fn is_verified(&self) -> bool {
        self.verified_fingerprint.is_some()
    }

    pub fn age_recipient(&self) -> &AgeRecipient {
        &self.age_recipient
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitResult {
    pub config_dir_created: bool,
    pub contact_store_created: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyResult {
    Verified,
    AlreadyVerified,
}

#[derive(Debug)]
pub struct ContactBook {
    config_dir: PathBuf,
}

#[derive(Debug, Error)]
pub enum ContactError {
    #[error("PQSend is not initialized at {}; run `pqsend init` first", .0.display())]
    NotInitialized(PathBuf),
    #[error("failed to create config directory {}: {source}", path.display())]
    CreateConfig {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("PQSend config path {} is a symbolic link", .0.display())]
    SymbolicLinkConfig(PathBuf),
    #[error("PQSend config path {} is not a directory", .0.display())]
    InvalidConfigDirectory(PathBuf),
    #[error("PQSend config directory {} is not private; require Unix mode 0700", .0.display())]
    InsecureConfigPermissions(PathBuf),
    #[error("failed to inspect PQSend config directory {}: {source}", path.display())]
    InspectConfig {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to read contact store {}: {source}", path.display())]
    ReadStore {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("contact store {} is not valid experimental TOML: {source}", path.display())]
    ParseStore {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error(
        "contact store {} uses old format `{format}`; re-import and re-verify contacts explicitly",
        path.display()
    )]
    OldStoreFormat { path: PathBuf, format: String },
    #[error(
        "contact store {} uses unsupported format `{format}`; expected `{CONTACT_STORE_FORMAT}`",
        path.display()
    )]
    UnsupportedStoreFormat { path: PathBuf, format: String },
    #[error("failed to serialize the contact store: {0}")]
    SerializeStore(#[from] toml::ser::Error),
    #[error("failed to write contact store {}: {source}", path.display())]
    WriteStore {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("contact store path {} is a symbolic link", .0.display())]
    SymbolicLinkStore(PathBuf),
    #[error("contact store path {} is not a regular file", .0.display())]
    InvalidStoreFile(PathBuf),
    #[error("contact store {} is not private; require Unix mode 0600", .0.display())]
    InsecureStorePermissions(PathBuf),
    #[error("invalid contact name `{name}`: {reason}")]
    InvalidName { name: String, reason: &'static str },
    #[error("contact name `{0}` already exists (names are ASCII-case-insensitive)")]
    DuplicateContactName(String),
    #[error("recipient is already stored for contact `{0}`")]
    DuplicateRecipient(String),
    #[error("contact store contains too many contacts; maximum is {MAX_CONTACTS}")]
    TooManyContacts,
    #[error("contact `{0}` does not exist")]
    MissingContact(String),
    #[error("failed to read recipient file {} as UTF-8 text: {source}", path.display())]
    ReadRecipient {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("recipient file is empty")]
    EmptyRecipient,
    #[error("recipient file contains secret age identity material")]
    SecretIdentityRecipient,
    #[error("recipient file must contain exactly one age X25519 recipient")]
    MultipleRecipients,
    #[error("recipient is not a valid supported age X25519 recipient")]
    InvalidRecipient,
    #[error("stored contact `{name}` has unsupported recipient type `{recipient_type}`")]
    InvalidRecipientType {
        name: String,
        recipient_type: String,
    },
    #[error("stored recipient for contact `{0}` is not canonical")]
    NonCanonicalRecipient(String),
    #[error("stored verified fingerprint for contact `{0}` is malformed")]
    MalformedVerifiedFingerprint(String),
    #[error("stored verified fingerprint for contact `{0}` does not match its recipient")]
    MismatchedVerifiedFingerprint(String),
    #[error("verification confirmation did not exactly match the full fingerprint")]
    VerificationMismatch,
}

#[derive(Debug, Deserialize)]
struct StoreFormatProbe {
    format: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SerializedContactStore {
    format: String,
    #[serde(default)]
    contacts: Vec<SerializedContact>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SerializedContact {
    name: String,
    recipient_type: String,
    recipient: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_fingerprint: Option<String>,
}

impl Default for SerializedContactStore {
    fn default() -> Self {
        Self {
            format: CONTACT_STORE_FORMAT.to_owned(),
            contacts: Vec::new(),
        }
    }
}

impl ContactBook {
    pub fn new(config_dir: impl Into<PathBuf>) -> Self {
        Self {
            config_dir: config_dir.into(),
        }
    }

    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    pub fn store_path(&self) -> PathBuf {
        self.config_dir.join(CONTACTS_FILE_NAME)
    }

    pub fn init(&self) -> Result<InitResult, ContactError> {
        let config_dir_created = !self.config_dir.exists();
        fs::create_dir_all(&self.config_dir).map_err(|source| ContactError::CreateConfig {
            path: self.config_dir.clone(),
            source,
        })?;
        if config_dir_created {
            make_config_private(&self.config_dir)?;
        }
        validate_config_directory_type(&self.config_dir)?;

        let store_path = self.store_path();
        let contact_store_created = if store_path.exists() {
            self.load_store()?;
            false
        } else {
            validate_config_directory(&self.config_dir)?;
            let contents = toml::to_string_pretty(&SerializedContactStore::default())?;
            if write_new_store(&self.config_dir, &store_path, contents.as_bytes())? {
                true
            } else {
                self.load_store()?;
                false
            }
        };

        Ok(InitResult {
            config_dir_created,
            contact_store_created,
        })
    }

    pub fn add(
        &self,
        name: &str,
        recipient_file: impl AsRef<Path>,
    ) -> Result<Contact, ContactError> {
        validate_contact_name(name)?;
        let recipient = read_recipient_file(recipient_file.as_ref())?;
        let canonical_recipient = recipient.to_string();

        let mut contacts = self.load_store()?;
        if contacts
            .iter()
            .any(|contact| contact.name.eq_ignore_ascii_case(name))
        {
            return Err(ContactError::DuplicateContactName(name.to_owned()));
        }
        if let Some(existing) = contacts
            .iter()
            .find(|contact| contact.recipient == canonical_recipient)
        {
            return Err(ContactError::DuplicateRecipient(existing.name.clone()));
        }
        if contacts.len() >= MAX_CONTACTS {
            return Err(ContactError::TooManyContacts);
        }

        let contact = resolve_contact(
            SerializedContact {
                name: name.to_owned(),
                recipient_type: CONTACT_RECIPIENT_TYPE.to_owned(),
                recipient: canonical_recipient,
                verified_fingerprint: None,
            },
            false,
        )?;
        contacts.push(contact.clone());
        self.save_store(&contacts)?;

        Ok(contact)
    }

    pub fn list(&self) -> Result<Vec<Contact>, ContactError> {
        let mut contacts = self.load_store()?;
        contacts.sort_by(|left, right| {
            left.name
                .to_ascii_lowercase()
                .cmp(&right.name.to_ascii_lowercase())
        });
        Ok(contacts)
    }

    pub fn contact(&self, name: &str) -> Result<Contact, ContactError> {
        find_contact(self.load_store()?, name)
    }

    pub fn fingerprint(&self, name: &str) -> Result<String, ContactError> {
        Ok(self.contact(name)?.full_fingerprint)
    }

    pub fn verify(&self, name: &str, confirmation: &str) -> Result<VerifyResult, ContactError> {
        let mut contacts = self.load_store()?;
        let contact = contacts
            .iter_mut()
            .find(|contact| contact.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| ContactError::MissingContact(name.to_owned()))?;

        if confirmation != contact.full_fingerprint {
            return Err(ContactError::VerificationMismatch);
        }
        if contact.is_verified() {
            return Ok(VerifyResult::AlreadyVerified);
        }

        contact.verified_fingerprint = Some(contact.full_fingerprint.clone());
        self.save_store(&contacts)?;
        Ok(VerifyResult::Verified)
    }

    fn load_store(&self) -> Result<Vec<Contact>, ContactError> {
        validate_config_directory(&self.config_dir).map_err(|error| match error {
            ContactError::InspectConfig { source, .. }
                if source.kind() == io::ErrorKind::NotFound =>
            {
                ContactError::NotInitialized(self.config_dir.clone())
            }
            other => other,
        })?;
        let store_path = self.store_path();
        validate_store_file(&store_path)?;
        let contents = read_bounded_regular_utf8_file(&store_path, MAX_CONTACT_STORE_BYTES)
            .map_err(|source| {
                if source.kind() == io::ErrorKind::NotFound {
                    ContactError::NotInitialized(self.config_dir.clone())
                } else {
                    ContactError::ReadStore {
                        path: store_path.clone(),
                        source,
                    }
                }
            })?;
        validate_config_directory(&self.config_dir)?;
        validate_store_file(&store_path)?;
        validate_store_format(&store_path, &contents)?;
        let store: SerializedContactStore =
            toml::from_str(&contents).map_err(|source| ContactError::ParseStore {
                path: store_path.clone(),
                source,
            })?;
        if store.contacts.len() > MAX_CONTACTS {
            return Err(ContactError::TooManyContacts);
        }

        let mut contacts = Vec::with_capacity(store.contacts.len());
        for record in store.contacts {
            let contact = resolve_contact(record, true)?;
            if contacts
                .iter()
                .any(|existing: &Contact| existing.name.eq_ignore_ascii_case(&contact.name))
            {
                return Err(ContactError::DuplicateContactName(contact.name));
            }
            if let Some(existing) = contacts
                .iter()
                .find(|existing| existing.recipient == contact.recipient)
            {
                return Err(ContactError::DuplicateRecipient(existing.name.clone()));
            }
            contacts.push(contact);
        }
        Ok(contacts)
    }

    fn save_store(&self, contacts: &[Contact]) -> Result<(), ContactError> {
        validate_config_directory(&self.config_dir)?;
        let store_path = self.store_path();
        validate_store_file(&store_path)?;
        let store = SerializedContactStore {
            format: CONTACT_STORE_FORMAT.to_owned(),
            contacts: contacts
                .iter()
                .map(|contact| SerializedContact {
                    name: contact.name.clone(),
                    recipient_type: CONTACT_RECIPIENT_TYPE.to_owned(),
                    recipient: contact.recipient.clone(),
                    verified_fingerprint: contact.verified_fingerprint.clone(),
                })
                .collect(),
        };
        let contents = toml::to_string_pretty(&store)?;
        replace_store_atomically(&self.config_dir, &store_path, contents.as_bytes())
    }
}

pub fn full_fingerprint(recipient: &AgeRecipient) -> String {
    let digest = contact_digest(recipient);
    format!("{CONTACT_FINGERPRINT_PREFIX}{}", hex(&digest))
}

pub fn short_fingerprint(recipient: &AgeRecipient) -> String {
    hex(&contact_digest(recipient)[..12])
}

fn contact_digest(recipient: &AgeRecipient) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_DOMAIN);
    hasher.update(recipient.to_string().as_bytes());
    hasher.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn resolve_contact(
    record: SerializedContact,
    require_canonical: bool,
) -> Result<Contact, ContactError> {
    validate_contact_name(&record.name)?;
    if record.recipient_type != CONTACT_RECIPIENT_TYPE {
        return Err(ContactError::InvalidRecipientType {
            name: record.name,
            recipient_type: record.recipient_type,
        });
    }

    let age_recipient = record
        .recipient
        .parse::<AgeRecipient>()
        .map_err(|_| ContactError::InvalidRecipient)?;
    let canonical_recipient = age_recipient.to_string();
    if require_canonical && canonical_recipient != record.recipient {
        return Err(ContactError::NonCanonicalRecipient(record.name));
    }
    let computed_fingerprint = full_fingerprint(&age_recipient);
    if let Some(stored) = &record.verified_fingerprint {
        if !is_full_fingerprint(stored) {
            return Err(ContactError::MalformedVerifiedFingerprint(record.name));
        }
        if stored != &computed_fingerprint {
            return Err(ContactError::MismatchedVerifiedFingerprint(record.name));
        }
    }

    Ok(Contact {
        name: record.name,
        recipient_type: CONTACT_RECIPIENT_TYPE,
        recipient: canonical_recipient.clone(),
        full_fingerprint: computed_fingerprint,
        short_fingerprint: short_fingerprint(&age_recipient),
        age_recipient,
        verified_fingerprint: record.verified_fingerprint,
    })
}

fn find_contact(contacts: Vec<Contact>, name: &str) -> Result<Contact, ContactError> {
    contacts
        .into_iter()
        .find(|contact| contact.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| ContactError::MissingContact(name.to_owned()))
}

fn validate_store_format(path: &Path, contents: &str) -> Result<(), ContactError> {
    let probe: StoreFormatProbe =
        toml::from_str(contents).map_err(|source| ContactError::ParseStore {
            path: path.to_path_buf(),
            source,
        })?;
    if probe.format == "experimental-v0" {
        return Err(ContactError::OldStoreFormat {
            path: path.to_path_buf(),
            format: probe.format,
        });
    }
    if probe.format != CONTACT_STORE_FORMAT {
        return Err(ContactError::UnsupportedStoreFormat {
            path: path.to_path_buf(),
            format: probe.format,
        });
    }
    Ok(())
}

fn validate_contact_name(name: &str) -> Result<(), ContactError> {
    let invalid = |reason| ContactError::InvalidName {
        name: name.to_owned(),
        reason,
    };

    if name.is_empty() || name.len() > 64 {
        return Err(invalid("must contain 1 to 64 ASCII characters"));
    }
    if name.starts_with('.') {
        return Err(invalid("must not start with `.`"));
    }
    if name.contains("..") {
        return Err(invalid("must not contain path traversal patterns"));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(invalid(
            "allowed characters are ASCII letters, numbers, `_`, `-`, and `.`",
        ));
    }
    Ok(())
}

fn read_recipient_file(path: &Path) -> Result<AgeRecipient, ContactError> {
    let contents =
        read_bounded_regular_utf8_file(path, MAX_RECIPIENT_FILE_BYTES).map_err(|source| {
            ContactError::ReadRecipient {
                path: path.to_path_buf(),
                source,
            }
        })?;
    if contains_ascii_case_insensitive(&contents, b"AGE-SECRET-KEY-") {
        return Err(ContactError::SecretIdentityRecipient);
    }

    let keys = contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>();
    match keys.as_slice() {
        [] => Err(ContactError::EmptyRecipient),
        [recipient] => recipient
            .parse::<AgeRecipient>()
            .map_err(|_| ContactError::InvalidRecipient),
        _ => Err(ContactError::MultipleRecipients),
    }
}

fn read_bounded_regular_utf8_file(path: &Path, maximum: usize) -> io::Result<String> {
    validate_regular_file_size(&fs::metadata(path)?, maximum)?;

    let file = File::open(path)?;
    validate_regular_file_size(&file.metadata()?, maximum)?;

    let read_limit = u64::try_from(maximum)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "platform size overflow"))?
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "platform size overflow"))?;
    let mut bytes = Vec::new();
    file.take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds the supported size limit",
        ));
    }

    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "file is not UTF-8"))
}

fn validate_regular_file_size(metadata: &fs::Metadata, maximum: usize) -> io::Result<()> {
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must be a regular file",
        ));
    }
    let maximum = u64::try_from(maximum)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "platform size overflow"))?;
    if metadata.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds the supported size limit",
        ));
    }
    Ok(())
}

fn contains_ascii_case_insensitive(text: &str, pattern: &[u8]) -> bool {
    text.as_bytes()
        .windows(pattern.len())
        .any(|window| window.eq_ignore_ascii_case(pattern))
}

fn is_full_fingerprint(value: &str) -> bool {
    value
        .strip_prefix(CONTACT_FINGERPRINT_PREFIX)
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
}

fn validate_config_directory(path: &Path) -> Result<(), ContactError> {
    let metadata = validate_config_directory_type(path)?;
    validate_config_permissions(path, &metadata)
}

fn validate_config_directory_type(path: &Path) -> Result<fs::Metadata, ContactError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ContactError::InspectConfig {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(ContactError::SymbolicLinkConfig(path.to_path_buf()));
    }
    if !metadata.is_dir() {
        return Err(ContactError::InvalidConfigDirectory(path.to_path_buf()));
    }
    Ok(metadata)
}

fn validate_store_file(path: &Path) -> Result<(), ContactError> {
    let metadata = validate_store_file_type(path)?;
    validate_store_permissions(path, &metadata)
}

fn validate_store_file_type(path: &Path) -> Result<fs::Metadata, ContactError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            ContactError::NotInitialized(
                path.parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| path.to_path_buf()),
            )
        } else {
            ContactError::ReadStore {
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    if metadata.file_type().is_symlink() {
        return Err(ContactError::SymbolicLinkStore(path.to_path_buf()));
    }
    if !metadata.is_file() {
        return Err(ContactError::InvalidStoreFile(path.to_path_buf()));
    }
    Ok(metadata)
}

#[cfg(unix)]
fn make_config_private(path: &Path) -> Result<(), ContactError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
        ContactError::CreateConfig {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn make_config_private(_path: &Path) -> Result<(), ContactError> {
    Ok(())
}

#[cfg(unix)]
fn validate_config_permissions(path: &Path, metadata: &fs::Metadata) -> Result<(), ContactError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(ContactError::InsecureConfigPermissions(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_config_permissions(_path: &Path, _metadata: &fs::Metadata) -> Result<(), ContactError> {
    Ok(())
}

#[cfg(unix)]
fn validate_store_permissions(path: &Path, metadata: &fs::Metadata) -> Result<(), ContactError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(ContactError::InsecureStorePermissions(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_store_permissions(_path: &Path, _metadata: &fs::Metadata) -> Result<(), ContactError> {
    Ok(())
}

fn write_new_store(
    config_dir: &Path,
    store_path: &Path,
    contents: &[u8],
) -> Result<bool, ContactError> {
    let temporary = prepare_store_file(config_dir, store_path, contents)?;
    match temporary.persist_noclobber(store_path) {
        Ok(_) => {
            sync_config_directory(config_dir, store_path)?;
            Ok(true)
        }
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(ContactError::WriteStore {
            path: store_path.to_path_buf(),
            source: error.error,
        }),
    }
}

fn replace_store_atomically(
    config_dir: &Path,
    store_path: &Path,
    contents: &[u8],
) -> Result<(), ContactError> {
    let temporary = prepare_store_file(config_dir, store_path, contents)?;
    temporary
        .persist(store_path)
        .map_err(|error| ContactError::WriteStore {
            path: store_path.to_path_buf(),
            source: error.error,
        })?;
    sync_config_directory(config_dir, store_path)
}

fn prepare_store_file(
    config_dir: &Path,
    store_path: &Path,
    contents: &[u8],
) -> Result<NamedTempFile, ContactError> {
    let mut temporary = Builder::new()
        .prefix(".pqsend-contacts-")
        .tempfile_in(config_dir)
        .map_err(|source| ContactError::WriteStore {
            path: store_path.to_path_buf(),
            source,
        })?;
    make_store_private(temporary.as_file(), store_path)?;
    temporary
        .write_all(contents)
        .and_then(|_| temporary.flush())
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|source| ContactError::WriteStore {
            path: store_path.to_path_buf(),
            source,
        })?;
    Ok(temporary)
}

#[cfg(unix)]
fn make_store_private(file: &File, store_path: &Path) -> Result<(), ContactError> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|source| ContactError::WriteStore {
            path: store_path.to_path_buf(),
            source,
        })
}

#[cfg(not(unix))]
fn make_store_private(_file: &File, _store_path: &Path) -> Result<(), ContactError> {
    Ok(())
}

#[cfg(unix)]
fn sync_config_directory(config_dir: &Path, store_path: &Path) -> Result<(), ContactError> {
    File::open(config_dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| ContactError::WriteStore {
            path: store_path.to_path_buf(),
            source,
        })
}

#[cfg(not(unix))]
fn sync_config_directory(_config_dir: &Path, _store_path: &Path) -> Result<(), ContactError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use age::secrecy::ExposeSecret;
    use tempfile::TempDir;

    use super::*;

    fn recipient_pair() -> (String, String) {
        let identity = age::x25519::Identity::generate();
        (
            identity.to_string().expose_secret().to_owned(),
            identity.to_public().to_string(),
        )
    }

    fn parsed_recipient(recipient: &str) -> AgeRecipient {
        recipient.parse().expect("parse generated recipient")
    }

    fn initialized_book() -> (TempDir, ContactBook) {
        let temp_dir = TempDir::new().expect("create temporary directory");
        let config_dir = temp_dir.path().join("pqsend");
        let book = ContactBook::new(config_dir);
        book.init().expect("initialize contact book");
        (temp_dir, book)
    }

    fn write_recipient(temp_dir: &TempDir, contents: &str) -> PathBuf {
        let path = temp_dir.path().join("recipient.txt");
        fs::write(&path, contents).expect("write test recipient");
        path
    }

    fn write_store(book: &ContactBook, contents: &str) {
        fs::write(book.store_path(), contents).expect("write contact store");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(book.store_path(), fs::Permissions::from_mode(0o600))
                .expect("set store permissions");
        }
    }

    fn store_with(contact: &str) -> String {
        format!("format = \"{CONTACT_STORE_FORMAT}\"\n\n[[contacts]]\n{contact}\n")
    }

    #[test]
    fn init_is_idempotent_and_preserves_contacts() {
        let (temp_dir, book) = initialized_book();
        let (_, recipient) = recipient_pair();
        let path = write_recipient(&temp_dir, &recipient);
        book.add("Alice", path).expect("add contact");
        let before = fs::read_to_string(book.store_path()).expect("read store");

        let result = book.init().expect("initialize existing store");

        assert!(!result.config_dir_created);
        assert!(!result.contact_store_created);
        assert_eq!(
            before,
            fs::read_to_string(book.store_path()).expect("read preserved store")
        );
    }

    #[test]
    fn valid_x25519_import_is_canonicalized() {
        let (temp_dir, book) = initialized_book();
        let (_, recipient) = recipient_pair();
        let path = write_recipient(
            &temp_dir,
            &format!("\n # comment discarded\n  {recipient}  \r\n"),
        );

        let contact = book.add("Alice", path).expect("add contact");

        assert_eq!(contact.recipient_type, CONTACT_RECIPIENT_TYPE);
        assert_eq!(contact.recipient, recipient);
        assert_eq!(contact.age_recipient().to_string(), recipient);
        let stored = fs::read_to_string(book.store_path()).expect("read store");
        assert!(stored.contains("format = \"experimental-v1\""));
        assert!(stored.contains("recipient_type = \"age-x25519\""));
        assert!(stored.contains(&format!("recipient = \"{recipient}\"")));
        assert!(!stored.contains("comment discarded"));
        assert!(!stored.contains("fingerprint ="));
        assert!(!stored.contains("verified ="));
    }

    #[test]
    fn invalid_recipient_inputs_are_rejected() {
        let (temp_dir, book) = initialized_book();
        let (identity, recipient) = recipient_pair();
        let cases = [
            ("empty", " \r\n# comment\n", "empty"),
            ("malformed", "not-an-age-recipient", "invalid"),
            ("identity", identity.as_str(), "secret"),
            (
                "ssh",
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN",
                "invalid",
            ),
            ("plugin", "age1plugin1example", "invalid"),
            ("passphrase", "scrypt", "invalid"),
            ("pq", "age1pq1example", "invalid"),
        ];

        for (name, contents, expected) in cases {
            let path = write_recipient(&temp_dir, contents);
            let error = book.add(name, path).expect_err("reject invalid recipient");
            assert!(
                matches!(
                    (expected, error),
                    ("empty", ContactError::EmptyRecipient)
                        | ("invalid", ContactError::InvalidRecipient)
                        | ("secret", ContactError::SecretIdentityRecipient)
                ),
                "unexpected result for {name}"
            );
        }

        let path = write_recipient(&temp_dir, &format!("{recipient}\n{recipient}\n"));
        assert!(matches!(
            book.add("multi", path),
            Err(ContactError::MultipleRecipients)
        ));
    }

    #[test]
    fn recipient_import_is_bounded_and_requires_a_regular_file() {
        let (temp_dir, book) = initialized_book();
        let oversized = "x".repeat(MAX_RECIPIENT_FILE_BYTES + 1);
        let path = write_recipient(&temp_dir, &oversized);
        let error = book
            .add("Oversized", &path)
            .expect_err("reject oversized recipient file");
        assert!(
            matches!(error, ContactError::ReadRecipient { source, .. } if source.kind() == io::ErrorKind::InvalidData)
        );

        let directory = temp_dir.path().join("recipient-directory");
        fs::create_dir(&directory).expect("create recipient directory");
        let error = book
            .add("Directory", directory)
            .expect_err("reject non-regular recipient path");
        assert!(
            matches!(error, ContactError::ReadRecipient { source, .. } if source.kind() == io::ErrorKind::InvalidInput)
        );
    }

    #[test]
    fn invalid_contact_names_and_missing_state_are_rejected() {
        let (temp_dir, book) = initialized_book();
        let (_, recipient) = recipient_pair();
        let path = write_recipient(&temp_dir, &recipient);
        for name in [
            "",
            ".",
            "..",
            ".hidden",
            "Alice Bob",
            "Alice/Bob",
            r"Alice\Bob",
            "Alice..Bob",
            "Alice@Bob",
            "é",
        ] {
            assert!(
                matches!(book.add(name, &path), Err(ContactError::InvalidName { .. })),
                "expected `{name}` to be rejected"
            );
        }
        assert!(matches!(
            book.add(&"a".repeat(65), &path),
            Err(ContactError::InvalidName { .. })
        ));

        let missing_path = temp_dir.path().join("missing-recipient.txt");
        assert!(matches!(
            book.add("MissingFile", &missing_path),
            Err(ContactError::ReadRecipient { path, .. }) if path == missing_path
        ));

        let uninitialized = ContactBook::new(temp_dir.path().join("uninitialized"));
        assert!(matches!(
            uninitialized.list(),
            Err(ContactError::NotInitialized(_))
        ));
    }

    #[test]
    fn fingerprints_are_stable_versioned_and_short_is_first_96_bits() {
        let (temp_dir, book) = initialized_book();
        let (_, recipient) = recipient_pair();
        let path = write_recipient(&temp_dir, &recipient);
        let first = book.add("Alice", &path).expect("add first contact");
        let first_full = first.full_fingerprint.clone();
        let first_short = first.short_fingerprint.clone();

        let other_book = ContactBook::new(temp_dir.path().join("other"));
        other_book.init().expect("initialize other book");
        fs::write(&path, format!("# comment\n\n  {recipient}\r\n")).expect("rewrite recipient");
        let second = other_book.add("Bob", path).expect("add second contact");

        assert_eq!(first_full, second.full_fingerprint);
        assert_eq!(first_short, second.short_fingerprint);
        assert!(first_full.starts_with(CONTACT_FINGERPRINT_PREFIX));
        assert_eq!(first_short.len(), 24);
        assert_eq!(
            first_short,
            first_full
                .strip_prefix(CONTACT_FINGERPRINT_PREFIX)
                .expect("fingerprint prefix")[..24]
        );
        let mut expected = Sha256::new();
        expected.update(b"pqsend-contact-fingerprint-v1\0age-x25519\0");
        expected.update(recipient.as_bytes());
        let expected_digest: [u8; 32] = expected.finalize().into();
        assert_eq!(
            first_full,
            format!("{CONTACT_FINGERPRINT_PREFIX}{}", hex(&expected_digest))
        );
        assert_eq!(
            book.fingerprint("alice").expect("full fingerprint"),
            first_full
        );
        assert!(!fs::read_to_string(book.store_path())
            .expect("read store")
            .contains(&first_short));
    }

    #[test]
    fn duplicate_names_and_recipients_are_rejected() {
        let (temp_dir, book) = initialized_book();
        let (_, recipient) = recipient_pair();
        let path = write_recipient(&temp_dir, &recipient);
        book.add("Bob", &path).expect("add Bob");

        assert!(matches!(
            book.add("bob", &path),
            Err(ContactError::DuplicateContactName(name)) if name == "bob"
        ));
        fs::write(&path, recipient.to_ascii_uppercase()).expect("write equivalent recipient");
        assert!(matches!(
            book.add("Alice", &path),
            Err(ContactError::DuplicateRecipient(name)) if name == "Bob"
        ));
        assert_eq!(book.contact("bOB").expect("resolve name").name, "Bob");
    }

    #[test]
    fn old_unknown_and_malformed_stores_are_rejected() {
        let (_temp_dir, book) = initialized_book();
        write_store(&book, "format = \"experimental-v0\"\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(book.config_dir(), fs::Permissions::from_mode(0o755))
                .expect("apply legacy config permissions");
            fs::set_permissions(book.store_path(), fs::Permissions::from_mode(0o644))
                .expect("apply legacy store permissions");
        }
        #[cfg(unix)]
        assert!(matches!(
            book.list(),
            Err(ContactError::InsecureConfigPermissions(_))
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(book.config_dir(), fs::Permissions::from_mode(0o700))
                .expect("restore config permissions");
            fs::set_permissions(book.store_path(), fs::Permissions::from_mode(0o600))
                .expect("restore store permissions");
        }
        let old_error = book.list().expect_err("reject old store");
        assert!(matches!(old_error, ContactError::OldStoreFormat { .. }));
        assert!(old_error.to_string().contains("re-import and re-verify"));

        write_store(&book, "format = \"experimental-v1\"\nunknown = true\n");
        assert!(matches!(book.list(), Err(ContactError::ParseStore { .. })));

        write_store(&book, "format = [");
        assert!(matches!(book.list(), Err(ContactError::ParseStore { .. })));
    }

    #[test]
    fn loaded_store_is_bounded_and_contact_count_is_limited() {
        let (_temp_dir, book) = initialized_book();
        write_store(&book, &"x".repeat(MAX_CONTACT_STORE_BYTES + 1));
        assert!(
            matches!(book.list(), Err(ContactError::ReadStore { source, .. }) if source.kind() == io::ErrorKind::InvalidData)
        );

        let (_, recipient) = recipient_pair();
        let record = format!(
            "\n[[contacts]]\nname = \"Alice\"\nrecipient_type = \"age-x25519\"\nrecipient = \"{recipient}\"\n"
        );
        write_store(
            &book,
            &format!(
                "format = \"{CONTACT_STORE_FORMAT}\"\n{}",
                record.repeat(MAX_CONTACTS + 1)
            ),
        );
        assert!(matches!(book.list(), Err(ContactError::TooManyContacts)));
    }

    #[test]
    fn loaded_records_must_be_canonical_unique_and_well_formed() {
        let (_temp_dir, book) = initialized_book();
        let (_, recipient) = recipient_pair();
        let record = format!(
            "name = \"Alice\"\nrecipient_type = \"age-x25519\"\nrecipient = \"{recipient}\""
        );

        write_store(
            &book,
            &store_with(&format!("{record}\nunknown = \"rejected\"")),
        );
        assert!(matches!(book.list(), Err(ContactError::ParseStore { .. })));

        write_store(
            &book,
            &store_with(
                "name = \"Alice\"\nrecipient_type = \"age-x25519\"\nrecipient = \"not-valid\"",
            ),
        );
        assert!(matches!(book.list(), Err(ContactError::InvalidRecipient)));

        write_store(
            &book,
            &store_with(&format!(
                "name = \"Alice\"\nrecipient_type = \"ssh\"\nrecipient = \"{recipient}\""
            )),
        );
        assert!(matches!(
            book.list(),
            Err(ContactError::InvalidRecipientType { .. })
        ));

        write_store(
            &book,
            &format!(
                "format = \"experimental-v1\"\n\n[[contacts]]\n{record}\n\n[[contacts]]\nname = \"alice\"\nrecipient_type = \"age-x25519\"\nrecipient = \"{recipient}\"\n"
            ),
        );
        assert!(matches!(
            book.list(),
            Err(ContactError::DuplicateContactName(_))
        ));

        let (_, other_recipient) = recipient_pair();
        write_store(
            &book,
            &format!(
                "format = \"experimental-v1\"\n\n[[contacts]]\n{record}\n\n[[contacts]]\nname = \"Other\"\nrecipient_type = \"age-x25519\"\nrecipient = \"{recipient}\"\n"
            ),
        );
        assert!(matches!(
            book.list(),
            Err(ContactError::DuplicateRecipient(_))
        ));

        let noncanonical = other_recipient.to_ascii_uppercase();
        noncanonical
            .parse::<AgeRecipient>()
            .expect("uppercase Bech32 recipient remains parseable");
        write_store(
            &book,
            &store_with(&format!(
                "name = \"Alice\"\nrecipient_type = \"age-x25519\"\nrecipient = \"{noncanonical}\""
            )),
        );
        assert!(matches!(
            book.list(),
            Err(ContactError::NonCanonicalRecipient(_))
        ));
    }

    #[test]
    fn verification_requires_exact_full_fingerprint_and_binds_recipient() {
        let (temp_dir, book) = initialized_book();
        let (_, recipient) = recipient_pair();
        let path = write_recipient(&temp_dir, &recipient);
        let contact = book.add("Alice", path).expect("add contact");

        assert!(matches!(
            book.verify("alice", &contact.short_fingerprint),
            Err(ContactError::VerificationMismatch)
        ));
        assert!(matches!(
            book.verify("Alice", &format!("{} ", contact.full_fingerprint)),
            Err(ContactError::VerificationMismatch)
        ));
        assert_eq!(
            book.verify("ALICE", &contact.full_fingerprint)
                .expect("verify"),
            VerifyResult::Verified
        );
        assert!(book.contact("Alice").expect("load contact").is_verified());
        let verified_store = fs::read_to_string(book.store_path()).expect("read verified store");
        assert!(verified_store.contains(&format!(
            "verified_fingerprint = \"{}\"",
            contact.full_fingerprint
        )));
        assert!(!verified_store.contains("\nverified ="));

        let (_, changed_recipient) = recipient_pair();
        let changed = store_with(&format!(
            "name = \"Alice\"\nrecipient_type = \"age-x25519\"\nrecipient = \"{changed_recipient}\"\nverified_fingerprint = \"{}\"",
            contact.full_fingerprint
        ));
        write_store(&book, &changed);
        assert!(matches!(
            book.list(),
            Err(ContactError::MismatchedVerifiedFingerprint(_))
        ));
    }

    #[test]
    fn stored_fingerprints_are_not_trusted() {
        let (_temp_dir, book) = initialized_book();
        let (_, recipient) = recipient_pair();
        let malformed = store_with(&format!(
            "name = \"Alice\"\nrecipient_type = \"age-x25519\"\nrecipient = \"{recipient}\"\nverified_fingerprint = \"wrong\""
        ));
        write_store(&book, &malformed);
        assert!(matches!(
            book.list(),
            Err(ContactError::MalformedVerifiedFingerprint(_))
        ));

        let unknown_fingerprint = store_with(&format!(
            "name = \"Alice\"\nrecipient_type = \"age-x25519\"\nrecipient = \"{recipient}\"\nfingerprint = \"{}\"",
            full_fingerprint(&parsed_recipient(&recipient))
        ));
        write_store(&book, &unknown_fingerprint);
        assert!(matches!(book.list(), Err(ContactError::ParseStore { .. })));

        for field in [
            "verified = true".to_owned(),
            format!(
                "full_fingerprint = \"{}\"",
                full_fingerprint(&parsed_recipient(&recipient))
            ),
            format!(
                "short_fingerprint = \"{}\"",
                short_fingerprint(&parsed_recipient(&recipient))
            ),
        ] {
            write_store(
                &book,
                &store_with(&format!(
                    "name = \"Alice\"\nrecipient_type = \"age-x25519\"\nrecipient = \"{recipient}\"\n{field}"
                )),
            );
            assert!(matches!(book.list(), Err(ContactError::ParseStore { .. })));
        }
    }

    #[test]
    fn changed_recipient_without_verification_binding_loads_unverified() {
        let (_temp_dir, book) = initialized_book();
        let (_, recipient) = recipient_pair();
        write_store(
            &book,
            &store_with(&format!(
                "name = \"Alice\"\nrecipient_type = \"age-x25519\"\nrecipient = \"{recipient}\""
            )),
        );

        assert!(!book.contact("Alice").expect("load contact").is_verified());
    }

    #[test]
    fn already_verified_contact_remains_bound_and_idempotent() {
        let (temp_dir, book) = initialized_book();
        let (_, recipient) = recipient_pair();
        let contact = book
            .add("Alice", write_recipient(&temp_dir, &recipient))
            .expect("add contact");
        book.verify("Alice", contact.full_fingerprint())
            .expect("verify contact");

        assert_eq!(
            book.verify("Alice", contact.full_fingerprint())
                .expect("verify again"),
            VerifyResult::AlreadyVerified
        );
        assert!(book.contact("Alice").expect("load contact").is_verified());
    }

    #[test]
    fn save_replaces_store_and_leaves_no_temporary_file() {
        let (temp_dir, book) = initialized_book();
        let (_, recipient) = recipient_pair();
        let path = write_recipient(&temp_dir, &recipient);
        let before = fs::read_to_string(book.store_path()).expect("read initial store");

        book.add("Alice", path).expect("add contact");

        let after = fs::read_to_string(book.store_path()).expect("read updated store");
        assert_ne!(before, after);
        assert!(fs::read_dir(book.config_dir())
            .expect("read config directory")
            .all(|entry| !entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".pqsend-contacts-")));
    }

    #[test]
    fn failed_atomic_replacement_preserves_existing_store() {
        let (_temp_dir, book) = initialized_book();
        let before = fs::read_to_string(book.store_path()).expect("read initial store");
        let missing_directory = book.config_dir().join("missing");

        assert!(
            replace_store_atomically(&missing_directory, &book.store_path(), b"replacement")
                .is_err()
        );
        assert_eq!(
            before,
            fs::read_to_string(book.store_path()).expect("read preserved store")
        );
    }

    #[test]
    fn existing_store_wins_new_store_publication_race() {
        let (_temp_dir, book) = initialized_book();
        write_store(&book, "format = \"experimental-v1\"\nunknown = true\n");
        let before = fs::read_to_string(book.store_path()).expect("read existing store");
        let replacement =
            toml::to_string_pretty(&SerializedContactStore::default()).expect("serialize store");

        assert!(!write_new_store(
            book.config_dir(),
            &book.store_path(),
            replacement.as_bytes()
        )
        .expect("existing store wins"));
        assert_eq!(
            before,
            fs::read_to_string(book.store_path()).expect("read preserved store")
        );
        assert!(matches!(book.list(), Err(ContactError::ParseStore { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn unix_store_and_config_safety_is_enforced() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let (_temp_dir, book) = initialized_book();
        assert_eq!(
            fs::metadata(book.config_dir())
                .expect("config metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(book.store_path())
                .expect("store metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        fs::set_permissions(book.store_path(), fs::Permissions::from_mode(0o644))
            .expect("make store public");
        assert!(matches!(
            book.list(),
            Err(ContactError::InsecureStorePermissions(_))
        ));
        fs::set_permissions(book.store_path(), fs::Permissions::from_mode(0o600))
            .expect("restore store permissions");

        fs::set_permissions(book.config_dir(), fs::Permissions::from_mode(0o755))
            .expect("make config public");
        assert!(matches!(
            book.list(),
            Err(ContactError::InsecureConfigPermissions(_))
        ));
        fs::set_permissions(book.config_dir(), fs::Permissions::from_mode(0o700))
            .expect("restore config permissions");

        let real_store = book.config_dir().join("real.toml");
        fs::rename(book.store_path(), &real_store).expect("move store");
        symlink(&real_store, book.store_path()).expect("symlink store");
        assert!(matches!(
            book.list(),
            Err(ContactError::SymbolicLinkStore(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_config_is_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp_dir = TempDir::new().expect("temporary directory");
        let real = temp_dir.path().join("real");
        fs::create_dir(&real).expect("create real directory");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700))
            .expect("set real permissions");
        let linked = temp_dir.path().join("linked");
        symlink(&real, &linked).expect("create config symlink");
        let book = ContactBook::new(linked);

        assert!(matches!(
            book.init(),
            Err(ContactError::SymbolicLinkConfig(_))
        ));
    }
}
