use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const CONTACTS_FILE_NAME: &str = "contacts.toml";
pub const CONTACT_STORE_FORMAT: &str = "experimental-v0";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Contact {
    pub name: String,
    pub public_key: String,
    pub fingerprint: String,
    pub verified: bool,
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
    #[error("invalid contact name `{name}`: {reason}")]
    InvalidName { name: String, reason: &'static str },
    #[error("contact `{0}` already exists")]
    DuplicateContact(String),
    #[error("contact `{0}` does not exist")]
    MissingContact(String),
    #[error("failed to read public key file {} as UTF-8 text: {source}", path.display())]
    ReadPublicKey {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("public key text is empty after normalization")]
    EmptyPublicKey,
}

#[derive(Debug, Deserialize, Serialize)]
struct ContactStore {
    format: String,
    #[serde(default)]
    contacts: Vec<Contact>,
}

impl Default for ContactStore {
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

        let store_path = self.store_path();
        let store = toml::to_string_pretty(&ContactStore::default())?;
        let contact_store_created = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&store_path)
        {
            Ok(mut file) => {
                file.write_all(store.as_bytes())
                    .map_err(|source| ContactError::WriteStore {
                        path: store_path.clone(),
                        source,
                    })?;
                true
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => false,
            Err(source) => {
                return Err(ContactError::WriteStore {
                    path: store_path,
                    source,
                });
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
        public_key_file: impl AsRef<Path>,
    ) -> Result<Contact, ContactError> {
        validate_contact_name(name)?;

        let public_key_file = public_key_file.as_ref();
        let public_key =
            fs::read_to_string(public_key_file).map_err(|source| ContactError::ReadPublicKey {
                path: public_key_file.to_path_buf(),
                source,
            })?;
        let public_key = normalize_public_key(&public_key)?;

        let mut store = self.load_store()?;
        if store.contacts.iter().any(|contact| contact.name == name) {
            return Err(ContactError::DuplicateContact(name.to_owned()));
        }

        let contact = Contact {
            name: name.to_owned(),
            fingerprint: fingerprint(&public_key),
            public_key,
            verified: false,
        };
        store.contacts.push(contact.clone());
        self.save_store(&store)?;

        Ok(contact)
    }

    pub fn list(&self) -> Result<Vec<Contact>, ContactError> {
        let mut contacts = self.load_store()?.contacts;
        contacts.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(contacts)
    }

    pub fn fingerprint(&self, name: &str) -> Result<String, ContactError> {
        self.load_store()?
            .contacts
            .into_iter()
            .find(|contact| contact.name == name)
            .map(|contact| contact.fingerprint)
            .ok_or_else(|| ContactError::MissingContact(name.to_owned()))
    }

    pub fn verify(&self, name: &str) -> Result<VerifyResult, ContactError> {
        let mut store = self.load_store()?;
        let contact = store
            .contacts
            .iter_mut()
            .find(|contact| contact.name == name)
            .ok_or_else(|| ContactError::MissingContact(name.to_owned()))?;

        if contact.verified {
            return Ok(VerifyResult::AlreadyVerified);
        }

        contact.verified = true;
        self.save_store(&store)?;
        Ok(VerifyResult::Verified)
    }

    fn load_store(&self) -> Result<ContactStore, ContactError> {
        let store_path = self.store_path();
        reject_symbolic_link(&store_path)?;
        let contents = fs::read_to_string(&store_path).map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                ContactError::NotInitialized(self.config_dir.clone())
            } else {
                ContactError::ReadStore {
                    path: store_path.clone(),
                    source,
                }
            }
        })?;
        let store: ContactStore =
            toml::from_str(&contents).map_err(|source| ContactError::ParseStore {
                path: store_path.clone(),
                source,
            })?;

        if store.format != CONTACT_STORE_FORMAT {
            return Err(ContactError::UnsupportedStoreFormat {
                path: store_path,
                format: store.format,
            });
        }

        Ok(store)
    }

    fn save_store(&self, store: &ContactStore) -> Result<(), ContactError> {
        let store_path = self.store_path();
        reject_symbolic_link(&store_path)?;
        let contents = toml::to_string_pretty(store)?;
        fs::write(&store_path, contents).map_err(|source| ContactError::WriteStore {
            path: store_path,
            source,
        })
    }
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

fn normalize_public_key(public_key: &str) -> Result<String, ContactError> {
    let normalized = public_key.replace("\r\n", "\n").replace('\r', "\n");
    let normalized = normalized.trim();
    if normalized.is_empty() {
        return Err(ContactError::EmptyPublicKey);
    }
    Ok(normalized.to_owned())
}

fn fingerprint(normalized_public_key: &str) -> String {
    let digest = Sha256::digest(normalized_public_key.as_bytes());
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();

    hex.as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).expect("uppercase hexadecimal is valid UTF-8"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn reject_symbolic_link(path: &Path) -> Result<(), ContactError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(ContactError::SymbolicLinkStore(path.to_path_buf()))
        }
        Ok(_) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ContactError::ReadStore {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    fn initialized_book() -> (TempDir, ContactBook) {
        let temp_dir = TempDir::new().expect("create temporary directory");
        let config_dir = temp_dir.path().join("pqsend");
        let book = ContactBook::new(config_dir);
        book.init().expect("initialize contact book");
        (temp_dir, book)
    }

    fn write_key(temp_dir: &TempDir, contents: &str) -> PathBuf {
        let key_path = temp_dir.path().join("public-key.txt");
        fs::write(&key_path, contents).expect("write test key");
        key_path
    }

    #[test]
    fn init_creates_config_directory_and_contact_store() {
        let temp_dir = TempDir::new().expect("create temporary directory");
        let book = ContactBook::new(temp_dir.path().join("config").join("pqsend"));

        let result = book.init().expect("initialize contact book");

        assert!(result.config_dir_created);
        assert!(result.contact_store_created);
        assert!(book.config_dir().is_dir());
        assert!(book.store_path().is_file());
        assert!(book.list().expect("list contacts").is_empty());
    }

    #[test]
    fn init_is_idempotent_and_does_not_overwrite_contacts() {
        let (temp_dir, book) = initialized_book();
        let key_path = write_key(&temp_dir, "test public key");
        book.add("Alice", &key_path).expect("add contact");
        let before = fs::read_to_string(book.store_path()).expect("read contact store");

        let result = book.init().expect("initialize contact book again");

        assert!(!result.config_dir_created);
        assert!(!result.contact_store_created);
        assert_eq!(
            before,
            fs::read_to_string(book.store_path()).expect("read contact store")
        );
        assert_eq!(book.list().expect("list contacts").len(), 1);
    }

    #[test]
    fn add_imports_and_normalizes_public_key_file() {
        let (temp_dir, book) = initialized_book();
        let key_path = write_key(&temp_dir, " \r\nopaque key line 1\r\nline 2\r\n ");

        let contact = book.add("Alice_1", &key_path).expect("add contact");

        assert_eq!(contact.name, "Alice_1");
        assert_eq!(contact.public_key, "opaque key line 1\nline 2");
        assert!(!contact.verified);
        assert_eq!(book.list().expect("list contacts"), vec![contact]);
    }

    #[test]
    fn add_rejects_invalid_contact_names() {
        let (temp_dir, book) = initialized_book();
        let key_path = write_key(&temp_dir, "opaque key");
        let invalid_names = [
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
        ];

        for name in invalid_names {
            assert!(
                matches!(
                    book.add(name, &key_path),
                    Err(ContactError::InvalidName { .. })
                ),
                "expected `{name}` to be rejected"
            );
        }
        assert!(matches!(
            book.add(&"a".repeat(65), &key_path),
            Err(ContactError::InvalidName { .. })
        ));
    }

    #[test]
    fn add_rejects_duplicate_contact_names_case_sensitively() {
        let (temp_dir, book) = initialized_book();
        let key_path = write_key(&temp_dir, "opaque key");
        book.add("Alice", &key_path).expect("add contact");

        assert!(matches!(
            book.add("Alice", &key_path),
            Err(ContactError::DuplicateContact(name)) if name == "Alice"
        ));
        assert!(book.add("alice", &key_path).is_ok());
    }

    #[test]
    fn add_rejects_empty_public_key_text() {
        let (temp_dir, book) = initialized_book();
        let key_path = write_key(&temp_dir, " \r\n\t\r ");

        assert!(matches!(
            book.add("Alice", &key_path),
            Err(ContactError::EmptyPublicKey)
        ));
    }

    #[test]
    fn add_rejects_unreadable_public_key_files() {
        let (temp_dir, book) = initialized_book();
        let missing_key_path = temp_dir.path().join("missing-key.txt");

        assert!(matches!(
            book.add("Alice", &missing_key_path),
            Err(ContactError::ReadPublicKey { path, .. }) if path == missing_key_path
        ));
    }

    #[test]
    fn fingerprint_is_stable_for_normalized_public_key_text() {
        let (temp_dir, book) = initialized_book();
        let first_key = write_key(&temp_dir, "  opaque key  ");
        let first = book.add("Alice", &first_key).expect("add first contact");
        fs::write(&first_key, "\nopaque key\r\n").expect("rewrite test key");
        let second = book.add("Bob", &first_key).expect("add second contact");

        assert_eq!(first.fingerprint, second.fingerprint);
        assert_eq!(
            first.fingerprint,
            book.fingerprint("Alice").expect("fingerprint")
        );
        assert!(first
            .fingerprint
            .chars()
            .all(|character| character.is_ascii_hexdigit() || character == ' '));
        assert_eq!(first.fingerprint.split(' ').count(), 16);
    }

    #[test]
    fn line_ending_normalization_produces_stable_fingerprints() {
        let (temp_dir, book) = initialized_book();
        let key_path = write_key(&temp_dir, "line 1\nline 2\n");
        let lf = book.add("LF", &key_path).expect("add LF contact");
        fs::write(&key_path, "line 1\r\nline 2\r\n").expect("write CRLF key");
        let crlf = book.add("CRLF", &key_path).expect("add CRLF contact");
        fs::write(&key_path, "line 1\rline 2\r").expect("write CR key");
        let cr = book.add("CR", &key_path).expect("add CR contact");

        assert_eq!(lf.fingerprint, crlf.fingerprint);
        assert_eq!(lf.fingerprint, cr.fingerprint);
        assert_eq!(lf.public_key, crlf.public_key);
        assert_eq!(lf.public_key, cr.public_key);
    }

    #[test]
    fn verify_marks_contact_verified_and_is_idempotent() {
        let (temp_dir, book) = initialized_book();
        let key_path = write_key(&temp_dir, "opaque key");
        book.add("Alice", &key_path).expect("add contact");

        assert_eq!(
            book.verify("Alice").expect("verify"),
            VerifyResult::Verified
        );
        assert_eq!(
            book.verify("Alice").expect("verify again"),
            VerifyResult::AlreadyVerified
        );
        assert!(book.list().expect("list contacts")[0].verified);
    }

    #[test]
    fn fingerprint_and_verify_reject_missing_contacts() {
        let (_temp_dir, book) = initialized_book();

        assert!(matches!(
            book.fingerprint("Missing"),
            Err(ContactError::MissingContact(name)) if name == "Missing"
        ));
        assert!(matches!(
            book.verify("Missing"),
            Err(ContactError::MissingContact(name)) if name == "Missing"
        ));
    }

    #[test]
    fn commands_reject_missing_contact_store() {
        let temp_dir = TempDir::new().expect("create temporary directory");
        let book = ContactBook::new(temp_dir.path().join("pqsend"));
        let key_path = write_key(&temp_dir, "opaque key");

        assert!(matches!(
            book.add("Alice", &key_path),
            Err(ContactError::NotInitialized(_))
        ));
        assert!(matches!(book.list(), Err(ContactError::NotInitialized(_))));
    }

    #[cfg(unix)]
    #[test]
    fn commands_reject_symbolic_link_contact_store() {
        use std::os::unix::fs::symlink;

        let (_temp_dir, book) = initialized_book();
        let real_store_path = book.config_dir().join("real-contacts.toml");
        fs::rename(book.store_path(), &real_store_path).expect("move contact store");
        symlink(&real_store_path, book.store_path()).expect("create store symbolic link");

        assert!(matches!(
            book.list(),
            Err(ContactError::SymbolicLinkStore(path)) if path == book.store_path()
        ));
    }
}
