use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use directories::BaseDirs;
use pqsend_core::{Contact, ContactBook, VerifyResult};

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
    /// Manage contacts.
    Contact {
        #[command(subcommand)]
        command: ContactCommand,
    },
    /// Create a package for a contact.
    Pack {
        /// File or directory to package.
        input: PathBuf,
        /// Contact who should be able to open the package.
        #[arg(long)]
        to: String,
    },
    /// Open a package into a directory.
    Open {
        /// Package to open.
        package: PathBuf,
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
        Command::Pack { input, to } => {
            not_implemented(&format!("pack {} --to {to}", input.display()))
        }
        Command::Open { package, out } => not_implemented(&format!(
            "open {} --out {}",
            package.display(),
            out.display()
        )),
        Command::Inspect { package } => not_implemented(&format!("inspect {}", package.display())),
    };

    Ok(output)
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

fn not_implemented(command: &str) -> String {
    format!("pqsend {command}: not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn package_stubs_do_not_require_contact_config() {
        let output = execute(
            Command::Pack {
                input: PathBuf::from("example.txt"),
                to: "Alice".to_owned(),
            },
            None,
        )
        .expect("run package stub");

        assert_eq!(
            output,
            "pqsend pack example.txt --to Alice: not yet implemented"
        );
    }
}
