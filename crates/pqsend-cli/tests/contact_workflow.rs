#![cfg(not(windows))]

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use age::secrecy::ExposeSecret;
use pqsend_core::{
    full_fingerprint as recipient_full_fingerprint,
    short_fingerprint as recipient_short_fingerprint, AgeRecipient, PUBLIC_ENVELOPE_LEN,
};
use tempfile::TempDir;

fn pqsend(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pqsend"));
    command
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"));
    command
}

fn success(mut command: Command) -> Output {
    let output = command.output().expect("run pqsend");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn failure(mut command: Command) -> Output {
    let output = command.output().expect("run pqsend");
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn success_with_stdin(mut command: Command, input: &str) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pqsend");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(input.as_bytes())
        .expect("write child stdin");
    let output = child.wait_with_output().expect("wait for pqsend");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn init(home: &Path) {
    let mut command = pqsend(home);
    command.arg("init");
    success(command);
}

fn keypair(directory: &Path, prefix: &str) -> (PathBuf, PathBuf, String) {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();
    let identity_path = directory.join(format!("{prefix}-identity.txt"));
    let recipient_path = directory.join(format!("{prefix}-recipient.txt"));
    fs::write(
        &identity_path,
        format!("{}\n", identity.to_string().expose_secret()),
    )
    .expect("write identity");
    fs::write(&recipient_path, format!("# recipient\n{recipient}\n")).expect("write recipient");
    (identity_path, recipient_path, recipient)
}

fn parsed_recipient(recipient: &str) -> AgeRecipient {
    recipient.parse().expect("parse generated recipient")
}

fn full_fingerprint(recipient: &str) -> String {
    recipient_full_fingerprint(&parsed_recipient(recipient))
}

fn short_fingerprint(recipient: &str) -> String {
    recipient_short_fingerprint(&parsed_recipient(recipient))
}

fn decrypt_inner(package: &[u8], identity_file: &Path) -> Vec<u8> {
    let identity_text = fs::read_to_string(identity_file).expect("read identity");
    let identity = identity_text
        .trim()
        .parse::<age::x25519::Identity>()
        .expect("parse identity");
    let decryptor =
        age::Decryptor::new(&package[PUBLIC_ENVELOPE_LEN..]).expect("parse age ciphertext");
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .expect("decrypt age ciphertext");
    let mut inner = Vec::new();
    reader
        .read_to_end(&mut inner)
        .expect("read inner plaintext");
    inner
}

fn add_contact(home: &Path, name: &str, recipient_file: &Path) -> Output {
    let mut command = pqsend(home);
    command
        .arg("contact")
        .arg("add")
        .arg(name)
        .arg(recipient_file);
    success(command)
}

fn verify_contact(home: &Path, name: &str, fingerprint: &str) -> Output {
    let mut command = pqsend(home);
    command.arg("contact").arg("verify").arg(name);
    success_with_stdin(command, &format!("{fingerprint}\n"))
}

fn pack_to(
    home: &Path,
    input: &Path,
    contact: &str,
    package: &Path,
    allow_unverified: bool,
) -> Output {
    let mut command = pqsend(home);
    command.arg("pack").arg(input).arg("--to").arg(contact);
    if allow_unverified {
        command.arg("--allow-unverified");
    }
    command.arg("--out").arg(package);
    success(command)
}

fn open(home: &Path, package: &Path, identity: &Path, output_directory: &Path) -> Output {
    let mut command = pqsend(home);
    command
        .arg("open")
        .arg(package)
        .arg("--identity-file")
        .arg(identity)
        .arg("--out")
        .arg(output_directory);
    success(command)
}

fn config_dir(home: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home.join("Library")
            .join("Application Support")
            .join("pqsend")
    }
    #[cfg(not(target_os = "macos"))]
    {
        home.join(".config").join("pqsend")
    }
}

#[test]
fn contact_commands_add_fingerprint_verify_and_reject_bad_inputs() {
    let temporary = TempDir::new().expect("temporary directory");
    let home = temporary.path().join("home");
    let keys = temporary.path().join("keys");
    fs::create_dir_all(&keys).expect("create keys directory");
    init(&home);
    let (_identity, recipient_file, recipient) = keypair(&keys, "bob");
    let full = full_fingerprint(&recipient);
    let short = short_fingerprint(&recipient);

    let add_output = add_contact(&home, "Bob", &recipient_file);
    let add_stdout = String::from_utf8_lossy(&add_output.stdout);
    assert!(add_stdout.contains("Added contact Bob"));
    assert!(add_stdout.contains(&full));
    assert!(add_stdout.contains(&short));

    let mut fingerprint = pqsend(&home);
    fingerprint.arg("contact").arg("fingerprint").arg("bob");
    let fingerprint_output = success(fingerprint);
    let fingerprint_stdout = String::from_utf8_lossy(&fingerprint_output.stdout);
    assert!(fingerprint_stdout.contains("Contact: Bob"));
    assert!(fingerprint_stdout.contains(&recipient));
    assert!(fingerprint_stdout.contains(&full));
    assert!(fingerprint_stdout.contains(&short));

    let mut wrong_verify = pqsend(&home);
    wrong_verify.arg("contact").arg("verify").arg("Bob");
    let wrong_output = {
        let mut child = wrong_verify
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn pqsend");
        child
            .stdin
            .take()
            .expect("child stdin")
            .write_all(format!("{short}\n").as_bytes())
            .expect("write child stdin");
        child.wait_with_output().expect("wait for pqsend")
    };
    assert!(!wrong_output.status.success());
    assert!(String::from_utf8_lossy(&wrong_output.stderr)
        .contains("did not exactly match the full fingerprint"));

    let verify_output = verify_contact(&home, "bob", &full);
    assert!(String::from_utf8_lossy(&verify_output.stdout).contains("Marked contact Bob"));

    let invalid_path = keys.join("invalid.txt");
    fs::write(&invalid_path, "not-an-age-recipient\n").expect("write invalid recipient");
    let mut invalid_add = pqsend(&home);
    invalid_add
        .arg("contact")
        .arg("add")
        .arg("Invalid")
        .arg(invalid_path);
    assert!(String::from_utf8_lossy(&failure(invalid_add).stderr)
        .contains("not a valid supported age X25519 recipient"));

    let store_path = config_dir(&home).join("contacts.toml");
    fs::write(
        &store_path,
        format!(
            "format = \"experimental-v1\"\n\n[[contacts]]\nname = \"Unsupported\"\nrecipient_type = \"ssh\"\nrecipient = \"{recipient}\"\n"
        ),
    )
    .expect("write unsupported contact store");
    let mut list = pqsend(&home);
    list.arg("contact").arg("list");
    assert!(
        String::from_utf8_lossy(&failure(list).stderr).contains("unsupported recipient type `ssh`")
    );
}

#[test]
fn verified_contact_packs_and_decrypts_with_local_contact_receipt() {
    let temporary = TempDir::new().expect("temporary directory");
    let home = temporary.path().join("home");
    let keys = temporary.path().join("keys");
    fs::create_dir_all(&keys).expect("create keys directory");
    init(&home);
    let (identity, recipient_file, recipient) = keypair(&keys, "verified");
    add_contact(&home, "Bob", &recipient_file);
    verify_contact(&home, "Bob", &full_fingerprint(&recipient));
    let input = temporary.path().join("private.txt");
    let package = temporary.path().join("verified.pqsend");
    let opened = temporary.path().join("opened");
    fs::write(&input, b"verified contact payload").expect("write input");

    let output = pack_to(&home, &input, "bob", &package, false);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("Recipient source: contact"));
    assert!(stdout.contains("Contact name: Bob"));
    assert!(stdout.contains("Contact verification: verified"));
    assert!(stdout.contains(&format!(
        "Short fingerprint: {}",
        short_fingerprint(&recipient)
    )));
    open(&home, &package, &identity, &opened);
    assert_eq!(
        fs::read(opened.join("private.txt")).expect("read opened file"),
        b"verified contact payload"
    );
}

#[test]
fn unverified_contact_is_blocked_unless_explicitly_overridden() {
    let temporary = TempDir::new().expect("temporary directory");
    let home = temporary.path().join("home");
    let keys = temporary.path().join("keys");
    fs::create_dir_all(&keys).expect("create keys directory");
    init(&home);
    let (_identity, recipient_file, recipient) = keypair(&keys, "unverified");
    add_contact(&home, "Bob", &recipient_file);
    let input = temporary.path().join("private.txt");
    let blocked_package = temporary.path().join("blocked.pqsend");
    let explicit_package = temporary.path().join("explicit.pqsend");
    let override_package = temporary.path().join("override.pqsend");
    fs::write(&input, b"unverified contact payload").expect("write input");
    let store_path = config_dir(&home).join("contacts.toml");
    let store_before_override = fs::read(&store_path).expect("read store before override");

    let mut blocked = pqsend(&home);
    blocked
        .arg("pack")
        .arg(&input)
        .arg("--to")
        .arg("bob")
        .arg("--out")
        .arg(&blocked_package);
    let blocked_output = failure(blocked);
    let blocked_stderr = String::from_utf8_lossy(&blocked_output.stderr);
    assert!(blocked_stderr.contains("contact `Bob` is unverified"));
    assert!(blocked_stderr.contains(&full_fingerprint(&recipient)));
    assert!(blocked_stderr.contains("pqsend contact verify bob"));
    assert!(blocked_stderr.contains("--allow-unverified"));
    assert!(!blocked_package.exists());

    let mut explicit = pqsend(&home);
    explicit
        .arg("pack")
        .arg(&input)
        .arg("--recipient-file")
        .arg(&recipient_file)
        .arg("--out")
        .arg(&explicit_package);
    let explicit_output = success(explicit);
    assert!(String::from_utf8_lossy(&explicit_output.stdout)
        .contains("Recipient source: explicit recipient file"));

    let override_output = pack_to(&home, &input, "Bob", &override_package, true);
    assert!(String::from_utf8_lossy(&override_output.stdout)
        .contains("Contact verification: unverified; explicit override used"));
    assert_eq!(
        fs::read(&store_path).expect("read store after override"),
        store_before_override
    );

    let mut list = pqsend(&home);
    list.arg("contact").arg("list");
    let list_output = success(list);
    assert!(String::from_utf8_lossy(&list_output.stdout).contains("Bob\t"));
    assert!(String::from_utf8_lossy(&list_output.stdout).contains("\tno"));
}

#[test]
fn missing_contact_and_invalid_pack_argument_combinations_fail_closed() {
    let temporary = TempDir::new().expect("temporary directory");
    let home = temporary.path().join("home");
    let keys = temporary.path().join("keys");
    fs::create_dir_all(&keys).expect("create keys directory");
    init(&home);
    let (_identity, recipient_file, _recipient) = keypair(&keys, "arguments");
    let input = temporary.path().join("input.txt");
    fs::write(&input, b"arguments").expect("write input");

    let mut missing = pqsend(&home);
    missing
        .arg("pack")
        .arg(&input)
        .arg("--to")
        .arg("Missing")
        .arg("--out")
        .arg(temporary.path().join("missing.pqsend"));
    assert!(String::from_utf8_lossy(&failure(missing).stderr)
        .contains("contact `Missing` does not exist"));

    let mut both = pqsend(&home);
    both.arg("pack")
        .arg(&input)
        .arg("--recipient-file")
        .arg(&recipient_file)
        .arg("--to")
        .arg("Bob")
        .arg("--out")
        .arg(temporary.path().join("both.pqsend"));
    failure(both);

    let mut neither = pqsend(&home);
    neither
        .arg("pack")
        .arg(&input)
        .arg("--out")
        .arg(temporary.path().join("neither.pqsend"));
    failure(neither);

    let mut invalid_override = pqsend(&home);
    invalid_override
        .arg("pack")
        .arg(&input)
        .arg("--recipient-file")
        .arg(&recipient_file)
        .arg("--allow-unverified")
        .arg("--out")
        .arg(temporary.path().join("invalid-override.pqsend"));
    failure(invalid_override);
}

#[test]
fn contact_metadata_is_absent_from_package_bytes_and_inspection() {
    let temporary = TempDir::new().expect("temporary directory");
    let home = temporary.path().join("home");
    let keys = temporary.path().join("keys");
    fs::create_dir_all(&keys).expect("create keys directory");
    init(&home);
    let (identity, recipient_file, recipient) = keypair(&keys, "privacy");
    let contact_name = "ContactMetadataMustRemainLocal";
    let full = full_fingerprint(&recipient);
    let short = short_fingerprint(&recipient);
    add_contact(&home, contact_name, &recipient_file);
    verify_contact(&home, contact_name, &full);
    let input = temporary.path().join("input.txt");
    let package = temporary.path().join("private.pqsend");
    fs::write(&input, b"privacy").expect("write input");
    pack_to(&home, &input, contact_name, &package, false);

    let package_bytes = fs::read(&package).expect("read package");
    let inner_plaintext = decrypt_inner(&package_bytes, &identity);
    for forbidden in [contact_name, full.as_str(), short.as_str()] {
        assert!(
            !package_bytes
                .windows(forbidden.len())
                .any(|window| window == forbidden.as_bytes()),
            "package contains contact metadata `{forbidden}`"
        );
        assert!(
            !inner_plaintext
                .windows(forbidden.len())
                .any(|window| window == forbidden.as_bytes()),
            "encrypted inner plaintext contains contact metadata `{forbidden}`"
        );
    }

    let mut inspect = pqsend(&home);
    inspect.arg("inspect").arg(package);
    let inspect_output = success(inspect);
    let inspect_stdout = String::from_utf8_lossy(&inspect_output.stdout);
    assert!(!inspect_stdout.contains(contact_name));
    assert!(!inspect_stdout.contains(&full));
    assert!(!inspect_stdout.contains(&short));
    assert!(!inspect_stdout.contains("Contact verification"));
    assert!(!inspect_stdout.contains(&recipient));
}

#[test]
fn duplicate_contact_names_and_canonical_recipients_are_rejected() {
    let temporary = TempDir::new().expect("temporary directory");
    let home = temporary.path().join("home");
    let keys = temporary.path().join("keys");
    fs::create_dir_all(&keys).expect("create keys directory");
    init(&home);
    let (_identity, recipient_file, recipient) = keypair(&keys, "duplicate");
    add_contact(&home, "Bob", &recipient_file);

    let mut duplicate_name = pqsend(&home);
    duplicate_name
        .arg("contact")
        .arg("add")
        .arg("bob")
        .arg(&recipient_file);
    assert!(String::from_utf8_lossy(&failure(duplicate_name).stderr)
        .contains("names are ASCII-case-insensitive"));

    fs::write(&recipient_file, recipient.to_ascii_uppercase()).expect("write equivalent recipient");
    let mut duplicate_recipient = pqsend(&home);
    duplicate_recipient
        .arg("contact")
        .arg("add")
        .arg("Alice")
        .arg(recipient_file);
    assert!(
        String::from_utf8_lossy(&failure(duplicate_recipient).stderr)
            .contains("recipient is already stored for contact `Bob`")
    );
}
