use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "pqsend",
    version,
    about = "Local-first encrypted file packages (experimental skeleton)"
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

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Init => not_implemented("init"),
        Command::Contact { command } => match command {
            ContactCommand::Add {
                name,
                public_key_file,
            } => not_implemented(&format!("contact add {name} {}", public_key_file.display())),
            ContactCommand::List => not_implemented("contact list"),
            ContactCommand::Fingerprint { name } => {
                not_implemented(&format!("contact fingerprint {name}"));
            }
            ContactCommand::Verify { name } => {
                not_implemented(&format!("contact verify {name}"));
            }
        },
        Command::Pack { input, to } => {
            not_implemented(&format!("pack {} --to {to}", input.display()));
        }
        Command::Open { package, out } => not_implemented(&format!(
            "open {} --out {}",
            package.display(),
            out.display()
        )),
        Command::Inspect { package } => {
            not_implemented(&format!("inspect {}", package.display()));
        }
    }
}

fn not_implemented(command: &str) {
    println!("pqsend {command}: not yet implemented");
}
