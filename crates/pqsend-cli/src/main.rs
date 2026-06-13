#![forbid(unsafe_code)]

use std::error::Error;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use age::secrecy::{ExposeSecret, SecretString};
use clap::{Parser, Subcommand};
use directories::BaseDirs;
use pqsend_core::{
    create_package, open_package, AgeIdentity, AgeRecipient, Contact, ContactBook, PackageError,
    PublicEnvelope, VerifyResult, MAX_FILE_BYTES, MAX_PACKAGE_BYTES, PUBLIC_ENVELOPE_LEN,
};
use tempfile::{Builder, NamedTempFile};

const MAX_KEY_FILE_BYTES: usize = 16 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "pqsend",
    version,
    about = "Local-first encrypted file packages (experimental)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize local PQSend state.
    Init,
    /// Generate one age X25519 identity and its public recipient.
    Keygen {
        /// New private identity file.
        #[arg(long)]
        out: PathBuf,
        /// New public recipient file.
        #[arg(long)]
        public_out: PathBuf,
    },
    /// Manage contacts.
    Contact {
        #[command(subcommand)]
        command: ContactCommand,
    },
    /// Encrypt one file into a package using an explicit recipient file.
    Pack {
        /// Regular file to package.
        input: PathBuf,
        /// File containing exactly one age X25519 recipient.
        #[arg(long)]
        recipient_file: PathBuf,
        /// New package file.
        #[arg(long)]
        out: PathBuf,
    },
    /// Decrypt one package using an explicit identity file.
    Open {
        /// Package to open.
        package: PathBuf,
        /// File containing exactly one age X25519 identity.
        #[arg(long)]
        identity_file: PathBuf,
        /// Output directory.
        #[arg(long)]
        out: PathBuf,
    },
    /// Inspect public package metadata.
    Inspect {
        /// Package to inspect.
        package: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ContactCommand {
    /// Add a contact from a public key file.
    Add {
        /// Local name for the contact.
        name: String,
        /// File containing the contact's public key.
        public_key_file: PathBuf,
    },
    /// List contacts.
    List,
    /// Display a contact fingerprint.
    Fingerprint {
        /// Contact name.
        name: String,
    },
    /// Mark a contact as verified.
    Verify {
        /// Contact name.
        name: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = execute(cli.command, None);

    match result {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn default_config_dir() -> Result<PathBuf, Box<dyn Error>> {
    BaseDirs::new()
        .map(|base_dirs| base_dirs.config_dir().join("pqsend"))
        .ok_or_else(|| "could not determine an OS-appropriate PQSend config directory".into())
}

fn execute(command: Command, config_dir: Option<&Path>) -> Result<String, Box<dyn Error>> {
    let output = match command {
        Command::Init => {
            let contact_book = contact_book(config_dir)?;
            format_init(&contact_book, contact_book.init()?)
        }
        Command::Keygen { out, public_out } => keygen(&out, &public_out)?,
        Command::Contact { command } => {
            let contact_book = contact_book(config_dir)?;
            match command {
                ContactCommand::Add {
                    name,
                    public_key_file,
                } => {
                    let contact = contact_book.add(&name, public_key_file)?;
                    format!(
                        "Added contact {}\nFingerprint: {}\nVerified: no",
                        contact.name, contact.fingerprint
                    )
                }
                ContactCommand::List => format_contacts(&contact_book.list()?),
                ContactCommand::Fingerprint { name } => {
                    format!("{name}: {}", contact_book.fingerprint(&name)?)
                }
                ContactCommand::Verify { name } => match contact_book.verify(&name)? {
                    VerifyResult::Verified => format!("Marked contact {name} as verified."),
                    VerifyResult::AlreadyVerified => format!("Contact {name} is already verified."),
                },
            }
        }
        Command::Pack {
            input,
            recipient_file,
            out,
        } => pack(&input, &recipient_file, &out)?,
        Command::Open {
            package,
            identity_file,
            out,
        } => open(&package, &identity_file, &out)?,
        Command::Inspect { package } => inspect(&package)?,
    };

    Ok(output)
}

fn keygen(identity_path: &Path, recipient_path: &Path) -> Result<String, Box<dyn Error>> {
    let resolved_identity_path = resolve_destination(identity_path)?;
    let resolved_recipient_path = resolve_destination(recipient_path)?;
    if resolved_identity_path == resolved_recipient_path {
        return Err(cli_error(
            "identity and public recipient output paths must be different",
        ));
    }
    ensure_destination_absent(identity_path, "identity file")?;
    ensure_destination_absent(recipient_path, "recipient file")?;

    let identity = age::x25519::Identity::generate();
    let recipient_text = identity.to_public().to_string();
    let identity_text = identity.to_string();
    let recipient_file = format!("# PQSend age X25519 recipient\n{recipient_text}\n");

    let recipient_temporary =
        prepare_new_file(recipient_path, recipient_file.as_bytes(), "recipient file")?;
    persist_noclobber(recipient_temporary, recipient_path, "recipient file")?;
    let identity_temporary = prepare_identity_file(identity_path, &identity_text)?;
    persist_noclobber(identity_temporary, identity_path, "identity file")?;

    Ok(format!(
        "Generated age v1 X25519 key files.\nIdentity file: {}\nRecipient file: {}\nPrivate identity: keep secret\nPost-quantum secure: no",
        identity_path.display(),
        recipient_path.display()
    ))
}

fn pack(input: &Path, recipient_file: &Path, output: &Path) -> Result<String, Box<dyn Error>> {
    ensure_destination_absent(output, "package file")?;
    let recipient = read_recipient(recipient_file)?;
    let filename = input
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| cli_error("input file basename is not valid UTF-8"))?;
    let file_bytes = read_regular_file_bounded(input, MAX_FILE_BYTES, "input file")?;
    let package = create_package(filename, &file_bytes, &recipient)?;
    write_new_file(output, &package, "package file")?;

    Ok("Encrypted locally: yes\nOriginal filename hidden in package: yes\nRecipient source: explicit recipient file\nBackend: age v1 X25519\nPost-quantum secure: no\nKnown leakage: package size, transfer timing, and outer package filename".to_owned())
}

fn open(
    package_path: &Path,
    identity_file: &Path,
    output_directory: &Path,
) -> Result<String, Box<dyn Error>> {
    let existing_output_directory = validate_existing_output_directory(output_directory)?;
    let identity = read_identity(identity_file)?;
    let package = read_regular_file_bounded(package_path, MAX_PACKAGE_BYTES, "package file")?;
    let opened = open_package(&package, &identity)?;

    let output_directory = match existing_output_directory {
        Some(directory) => directory,
        None => create_private_output_directory(output_directory)?,
    };

    let output_path = output_directory.join(&opened.filename);
    write_new_file(&output_path, &opened.file_bytes, "output file")?;

    Ok(format!(
        "Decryption succeeded: yes\nIntegrity verified: yes\nOriginal filename restored: yes\nOutput path: {}\nBackend: age v1 X25519\nPost-quantum secure: no",
        output_path.display()
    ))
}

fn inspect(package_path: &Path) -> Result<String, Box<dyn Error>> {
    let package = read_regular_file_bounded(package_path, MAX_PACKAGE_BYTES, "package file")?;
    let envelope = PublicEnvelope::decode(&package)?;
    let encrypted_payload_len = usize::try_from(envelope.encrypted_payload_len())
        .map_err(|_| PackageError::EncryptedPayloadTooLarge)?;
    let expected_package_len = PUBLIC_ENVELOPE_LEN
        .checked_add(encrypted_payload_len)
        .ok_or(PackageError::PackageLengthMismatch)?;
    if package.len() != expected_package_len {
        return Err(PackageError::PackageLengthMismatch.into());
    }

    Ok(format!(
        "format: pqsend\nformat version: {}\npackage mode: single file\nbackend: age v1 X25519\nencrypted payload length: {}\ntotal package size: {}",
        envelope.version(),
        envelope.encrypted_payload_len(),
        package.len()
    ))
}

fn read_recipient(path: &Path) -> Result<AgeRecipient, Box<dyn Error>> {
    let key = read_single_key(path, "recipient file", true)?;
    Ok(key.expose_secret().parse()?)
}

fn read_identity(path: &Path) -> Result<AgeIdentity, Box<dyn Error>> {
    let key = read_single_key(path, "identity file", false)?;
    Ok(key.expose_secret().parse()?)
}

fn read_single_key(
    path: &Path,
    kind: &str,
    reject_secret_comments: bool,
) -> Result<SecretString, Box<dyn Error>> {
    let bytes = read_regular_file_bounded(path, MAX_KEY_FILE_BYTES, kind)?;
    let text = String::from_utf8(bytes).map_err(|_| cli_error(&format!("{kind} is not UTF-8")))?;
    let text = SecretString::from(text);
    let exposed_text = text.expose_secret();
    if reject_secret_comments && contains_ascii_case_insensitive(exposed_text, b"AGE-SECRET-KEY-") {
        return Err(cli_error(&format!("{kind} contains private key material")));
    }
    let mut key = None;

    for line in exposed_text.lines() {
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#') {
            if comment.bytes().any(|byte| byte.is_ascii_control()) {
                return Err(cli_error(&format!("{kind} contains an unsafe comment")));
            }
            continue;
        }
        if line.trim() != line || key.replace(line).is_some() {
            return Err(cli_error(&format!(
                "{kind} must contain exactly one unadorned key"
            )));
        }
    }

    key.map(SecretString::from)
        .ok_or_else(|| cli_error(&format!("{kind} does not contain a key")))
}

fn contains_ascii_case_insensitive(text: &str, pattern: &[u8]) -> bool {
    text.as_bytes()
        .windows(pattern.len())
        .any(|window| window.eq_ignore_ascii_case(pattern))
}

fn read_regular_file_bounded(
    path: &Path,
    maximum: usize,
    kind: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(cli_error(&format!("{kind} must be a regular file")));
    }
    let maximum_u64 = u64::try_from(maximum).map_err(|_| cli_error("platform size overflow"))?;
    if metadata.len() > maximum_u64 {
        return Err(cli_error(&format!(
            "{kind} exceeds the supported size limit"
        )));
    }

    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        return Err(cli_error(&format!("{kind} must be a regular file")));
    }
    if opened_metadata.len() > maximum_u64 {
        return Err(cli_error(&format!(
            "{kind} exceeds the supported size limit"
        )));
    }

    let read_limit = maximum_u64
        .checked_add(1)
        .ok_or_else(|| cli_error("platform size overflow"))?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened_metadata.len()).map_err(|_| cli_error("platform size overflow"))?,
    );
    file.take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(cli_error(&format!(
            "{kind} exceeds the supported size limit"
        )));
    }
    Ok(bytes)
}

fn validate_existing_output_directory(path: &Path) -> Result<Option<PathBuf>, Box<dyn Error>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(cli_error("output directory must not be a symbolic link"))
        }
        Ok(metadata) if metadata.is_dir() => Ok(Some(fs::canonicalize(path)?)),
        Ok(_) => Err(cli_error("output path exists and is not a directory")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn ensure_destination_absent(path: &Path, kind: &str) -> Result<(), Box<dyn Error>> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(cli_error(&format!("refusing to overwrite existing {kind}"))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn write_new_file(path: &Path, bytes: &[u8], kind: &str) -> Result<(), Box<dyn Error>> {
    let temporary = prepare_new_file(path, bytes, kind)?;
    persist_noclobber(temporary, path, kind)
}

fn prepare_new_file(
    path: &Path,
    bytes: &[u8],
    kind: &str,
) -> Result<NamedTempFile, Box<dyn Error>> {
    prepare_new_file_with(path, kind, |temporary| temporary.write_all(bytes))
}

fn prepare_identity_file(
    path: &Path,
    identity: &SecretString,
) -> Result<NamedTempFile, Box<dyn Error>> {
    prepare_new_file_with(path, "identity file", |temporary| {
        temporary.write_all(b"# PQSend age X25519 identity\n# KEEP THIS FILE SECRET\n")?;
        temporary.write_all(identity.expose_secret().as_bytes())?;
        temporary.write_all(b"\n")
    })
}

fn prepare_new_file_with(
    path: &Path,
    kind: &str,
    write: impl FnOnce(&mut NamedTempFile) -> io::Result<()>,
) -> Result<NamedTempFile, Box<dyn Error>> {
    ensure_destination_absent(path, kind)?;
    let parent = destination_parent(path);
    let mut temporary = Builder::new().prefix(".pqsend-").tempfile_in(parent)?;
    write(&mut temporary)?;
    temporary.as_file_mut().flush()?;
    temporary.as_file().sync_all()?;
    Ok(temporary)
}

fn destination_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn resolve_destination(path: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let filename = path
        .file_name()
        .ok_or_else(|| cli_error("output path must name a file"))?;
    Ok(fs::canonicalize(destination_parent(path))?.join(filename))
}

fn create_private_output_directory(path: &Path) -> Result<PathBuf, Box<dyn Error>> {
    create_directory_private(path)?;
    validate_existing_output_directory(path)?
        .ok_or_else(|| cli_error("output directory was not created"))
}

#[cfg(unix)]
fn create_directory_private(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_directory_private(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
}

fn persist_noclobber(
    temporary: NamedTempFile,
    destination: &Path,
    kind: &str,
) -> Result<(), Box<dyn Error>> {
    match temporary.persist_noclobber(destination) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            Err(cli_error(&format!("refusing to overwrite existing {kind}")))
        }
        Err(error) => Err(error.error.into()),
    }
}

fn cli_error(message: &str) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidInput, message).into()
}

fn contact_book(config_dir: Option<&Path>) -> Result<ContactBook, Box<dyn Error>> {
    Ok(ContactBook::new(match config_dir {
        Some(config_dir) => config_dir.to_path_buf(),
        None => default_config_dir()?,
    }))
}

fn format_init(contact_book: &ContactBook, result: pqsend_core::InitResult) -> String {
    match (result.config_dir_created, result.contact_store_created) {
        (true, true) => format!(
            "Initialized PQSend at {}\nCreated contact store {}",
            contact_book.config_dir().display(),
            contact_book.store_path().display()
        ),
        (_, true) => format!(
            "PQSend config directory already exists at {}\nCreated contact store {}",
            contact_book.config_dir().display(),
            contact_book.store_path().display()
        ),
        (_, false) => format!(
            "PQSend is already initialized at {}\nExisting contacts were preserved.",
            contact_book.config_dir().display()
        ),
    }
}

fn format_contacts(contacts: &[Contact]) -> String {
    if contacts.is_empty() {
        return "No contacts found.".to_owned();
    }

    let mut output = String::from("NAME\tFINGERPRINT\tVERIFIED");
    for contact in contacts {
        output.push_str(&format!(
            "\n{}\t{}\t{}",
            contact.name,
            contact.fingerprint,
            if contact.verified { "yes" } else { "no" }
        ));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn contact_list_output_includes_name_fingerprint_and_verification_status() {
        let contacts = [
            Contact {
                name: "Alice".to_owned(),
                public_key: "opaque key".to_owned(),
                fingerprint: "AAAA BBBB".to_owned(),
                verified: false,
            },
            Contact {
                name: "Bob".to_owned(),
                public_key: "another opaque key".to_owned(),
                fingerprint: "CCCC DDDD".to_owned(),
                verified: true,
            },
        ];

        let output = format_contacts(&contacts);

        assert!(output.contains("NAME\tFINGERPRINT\tVERIFIED"));
        assert!(output.contains("Alice\tAAAA BBBB\tno"));
        assert!(output.contains("Bob\tCCCC DDDD\tyes"));
    }

    #[test]
    fn empty_contact_list_has_clear_output() {
        assert_eq!(format_contacts(&[]), "No contacts found.");
    }

    #[test]
    fn temporary_file_is_created_in_destination_directory() {
        let directory = TempDir::new().expect("temporary directory");
        let destination = directory.path().join("output.bin");

        let temporary =
            prepare_new_file(&destination, b"contents", "test file").expect("prepare test file");
        let temporary_path = temporary.path().to_path_buf();

        assert_eq!(temporary.path().parent(), Some(directory.path()));
        drop(temporary);
        assert!(!temporary_path.exists());
    }

    #[test]
    fn failed_publication_removes_temporary_file() {
        let directory = TempDir::new().expect("temporary directory");
        let destination = directory.path().join("output.bin");
        let temporary = prepare_new_file(&destination, b"new contents", "test file")
            .expect("prepare test file");
        let temporary_path = temporary.path().to_path_buf();
        fs::write(&destination, b"existing contents").expect("write existing destination");

        assert!(persist_noclobber(temporary, &destination, "test file").is_err());
        assert!(!temporary_path.exists());
        assert_eq!(
            fs::read(destination).expect("read existing destination"),
            b"existing contents"
        );
    }
}
