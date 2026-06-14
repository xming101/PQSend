use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[cfg(unix)]
use std::os::unix::fs::{symlink, PermissionsExt};

use pqsend_core::MAX_FILE_BYTES;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

fn pqsend() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pqsend"))
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

fn keygen(directory: &Path, prefix: &str) -> (PathBuf, PathBuf) {
    let identity = directory.join(format!("{prefix}-identity.txt"));
    let recipient = directory.join(format!("{prefix}-recipient.txt"));
    let mut command = pqsend();
    command
        .arg("keygen")
        .arg("--out")
        .arg(&identity)
        .arg("--public-out")
        .arg(&recipient);
    success(command);
    (identity, recipient)
}

fn pack(input: &Path, recipient: &Path, package: &Path) -> Output {
    let mut command = pqsend();
    command
        .arg("pack")
        .arg(input)
        .arg("--recipient-file")
        .arg(recipient)
        .arg("--out")
        .arg(package);
    success(command)
}

fn open(package: &Path, identity: &Path, output_directory: &Path) -> Output {
    let mut command = pqsend();
    command
        .arg("open")
        .arg(package)
        .arg("--identity-file")
        .arg(identity)
        .arg("--out")
        .arg(output_directory);
    success(command)
}

fn receipt_value<'a>(stdout: &'a str, label: &str) -> &'a str {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix(label))
        .expect("receipt field")
}

fn assert_no_temporary_files(directory: &Path) {
    if !directory.exists() {
        return;
    }

    for entry in fs::read_dir(directory).expect("read directory") {
        let entry = entry.expect("read directory entry");
        assert!(
            !entry.file_name().to_string_lossy().starts_with(".pqsend-"),
            "temporary file remains at {}",
            entry.path().display()
        );
    }
}

fn packaged_file(
    directory: &Path,
    prefix: &str,
    filename: &str,
    contents: &[u8],
) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let (identity, recipient) = keygen(directory, prefix);
    let input = directory.join(filename);
    let package = directory.join(format!("{prefix}-bundle.pqsend"));
    fs::write(&input, contents).expect("write input");
    pack(&input, &recipient, &package);
    (identity, recipient, input, package)
}

#[test]
fn keygen_creates_identity_and_recipient_files() {
    let temporary = TempDir::new().expect("temporary directory");
    let identity = temporary.path().join("bob.agekey");
    let recipient = temporary.path().join("bob.agepub");
    let mut command = pqsend();
    command
        .arg("keygen")
        .arg("--out")
        .arg(&identity)
        .arg("--public-out")
        .arg(&recipient);

    let output = success(command);
    assert!(identity.is_file());
    assert!(recipient.is_file());
    let identity_text = fs::read_to_string(identity).expect("read identity");
    let recipient_text = fs::read_to_string(recipient).expect("read recipient");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!identity_text.is_empty());
    assert!(!recipient_text.is_empty());
    assert!(identity_text.contains("KEEP THIS FILE SECRET"));
    assert!(identity_text.contains("AGE-SECRET-KEY-"));
    assert!(recipient_text.lines().any(|line| line.starts_with("age1")));
    assert!(!recipient_text.contains("AGE-SECRET-KEY-"));
    assert!(!stdout.contains("AGE-SECRET-KEY-"));
    assert!(!stderr.contains("AGE-SECRET-KEY-"));
}

#[test]
fn keygen_refuses_to_overwrite_existing_key_files() {
    let temporary = TempDir::new().expect("temporary directory");
    let identity = temporary.path().join("identity.txt");
    let recipient = temporary.path().join("recipient.txt");
    fs::write(&identity, b"existing identity").expect("write existing identity");
    let mut command = pqsend();
    command
        .arg("keygen")
        .arg("--out")
        .arg(&identity)
        .arg("--public-out")
        .arg(&recipient);

    failure(command);

    assert_eq!(
        fs::read(identity).expect("read existing identity"),
        b"existing identity"
    );
    assert!(!recipient.exists());
}

#[test]
fn keygen_refuses_to_overwrite_existing_public_recipient_file() {
    let temporary = TempDir::new().expect("temporary directory");
    let identity = temporary.path().join("bob.agekey");
    let recipient = temporary.path().join("bob.agepub");
    fs::write(&recipient, b"existing recipient").expect("write existing recipient");
    let mut command = pqsend();
    command
        .arg("keygen")
        .arg("--out")
        .arg(&identity)
        .arg("--public-out")
        .arg(&recipient);

    failure(command);

    assert!(!identity.exists());
    assert_eq!(
        fs::read(recipient).expect("read existing recipient"),
        b"existing recipient"
    );
}

#[test]
fn keygen_rejects_equivalent_output_paths_without_leaving_private_key() {
    let temporary = TempDir::new().expect("temporary directory");
    let output_directory = temporary.path().join("outputs");
    fs::create_dir_all(output_directory.join("sub")).expect("create output directories");
    let identity = output_directory.join("same.txt");
    let recipient = output_directory.join("sub").join("..").join("same.txt");
    let mut command = pqsend();
    command
        .arg("keygen")
        .arg("--out")
        .arg(&identity)
        .arg("--public-out")
        .arg(recipient);

    let output = failure(command);

    assert!(!identity.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("paths must be different"));
}

#[test]
fn keygen_validation_failure_leaves_no_private_key() {
    let temporary = TempDir::new().expect("temporary directory");
    let identity = temporary.path().join("identity.txt");
    let recipient = temporary.path().join("missing").join("recipient.txt");
    let mut command = pqsend();
    command
        .arg("keygen")
        .arg("--out")
        .arg(&identity)
        .arg("--public-out")
        .arg(recipient);

    let output = failure(command);

    assert!(!identity.exists());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("recipient file parent directory does not exist"));
}

#[cfg(unix)]
#[test]
fn generated_identity_file_is_private() {
    let temporary = TempDir::new().expect("temporary directory");
    let (identity, _recipient) = keygen(temporary.path(), "permissions");
    let mode = fs::metadata(identity)
        .expect("identity metadata")
        .permissions()
        .mode()
        & 0o777;

    assert_eq!(mode, 0o600);
}

#[test]
fn generated_recipient_encrypts_and_generated_identity_decrypts() {
    let temporary = TempDir::new().expect("temporary directory");
    let contents = b"explicit key file round trip";
    let (identity, _recipient, _input, package) =
        packaged_file(temporary.path(), "round-trip", "private.txt", contents);
    let output_directory = temporary.path().join("opened");

    open(&package, &identity, &output_directory);

    assert_eq!(
        fs::read(output_directory.join("private.txt")).expect("read opened file"),
        contents
    );
}

#[test]
fn pack_creates_a_pqsend_file_and_prints_encryption_receipt() {
    let temporary = TempDir::new().expect("temporary directory");
    let (_identity, recipient) = keygen(temporary.path(), "pack");
    let input = temporary.path().join("document.txt");
    let package = temporary.path().join("opaque-bundle.pqsend");
    fs::write(&input, b"contents").expect("write input");

    let output = pack(&input, &recipient, &package);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let package_bytes = fs::read(&package).expect("read package");
    let package_hash = format!("{:x}", Sha256::digest(&package_bytes));

    assert!(package.is_file());
    assert!(stdout.contains("Security receipt (local CLI output only)"));
    assert!(stdout.contains("Operation: package creation"));
    assert!(stdout.contains(&format!("Package path: {}", package.display())));
    assert!(stdout.contains(&format!("Package SHA-256: {package_hash}")));
    receipt_value(
        &stdout,
        "Local receipt time (Unix seconds; not package metadata): ",
    )
    .parse::<f64>()
    .expect("numeric local receipt time");
    assert!(stdout.contains("Package format version: 1"));
    assert!(stdout.contains("Package mode: single file"));
    assert!(stdout.contains("Crypto backend/mode: age v1 X25519"));
    assert!(stdout.contains("Post-quantum status: no; current backend is X25519-only"));
    assert!(stdout.contains("Encrypted locally: yes"));
    assert!(stdout.contains("Original filename hidden from public package metadata: yes"));
    assert!(stdout.contains("Encrypted internal manifest: yes"));
    assert!(stdout.contains("Recipient source: explicit recipient file"));
    assert!(stdout.contains(
        "Known leakage: package size; transfer timing outside PQSend; outer package filename chosen by user"
    ));
    assert!(!stdout.contains("Transfer channel can decrypt"));
    assert!(!stdout.contains(&input.display().to_string()));
    assert!(!stdout.contains(&recipient.display().to_string()));
}

#[test]
fn open_restores_original_filename_and_prints_decryption_receipt() {
    let temporary = TempDir::new().expect("temporary directory");
    let (identity, _recipient, _input, package) =
        packaged_file(temporary.path(), "restore", "restored-name.txt", b"body");
    let output_directory = temporary.path().join("new-output-directory");

    let output = open(&package, &identity, &output_directory);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let package_hash = format!(
        "{:x}",
        Sha256::digest(fs::read(&package).expect("read package"))
    );
    let restored_output = fs::canonicalize(&output_directory)
        .expect("canonical output directory")
        .join("restored-name.txt");

    assert!(output_directory.join("restored-name.txt").is_file());
    assert!(stdout.contains("Security receipt (local CLI output only)"));
    assert!(stdout.contains("Operation: open/decrypt"));
    assert!(stdout.contains(&format!("Package path: {}", package.display())));
    assert!(stdout.contains(&format!("Package SHA-256: {package_hash}")));
    assert!(stdout.contains("Package format version: 1"));
    assert!(stdout.contains("Package mode: single file"));
    assert!(stdout.contains("Crypto backend/mode: age v1 X25519"));
    assert!(stdout.contains("Decryption succeeded: yes"));
    assert!(stdout.contains("Integrity verified: yes"));
    assert!(stdout.contains("Original filename restored: yes"));
    assert!(stdout.contains(&format!(
        "Restored output path: {}",
        restored_output.display()
    )));
    assert!(stdout.contains(
        "WARNING: sender identity and authorship are not verified; PQSend does not implement signatures"
    ));
    assert!(!stdout.contains("Sender identity verified: yes"));
    assert!(!stdout.contains("Authorship verified: yes"));
}

#[cfg(unix)]
#[test]
fn open_creates_private_output_directory() {
    let temporary = TempDir::new().expect("temporary directory");
    let (identity, _recipient, _input, package) =
        packaged_file(temporary.path(), "private-output", "secret.txt", b"body");
    let output_directory = temporary.path().join("new-output-directory");

    open(&package, &identity, &output_directory);

    let mode = fs::metadata(output_directory)
        .expect("output directory metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
}

#[test]
fn package_bytes_do_not_contain_original_filename() {
    let temporary = TempDir::new().expect("temporary directory");
    let filename = "private-original-filename.txt";
    let (_identity, _recipient, _input, package) =
        packaged_file(temporary.path(), "hidden", filename, b"body");

    let package_bytes = fs::read(package).expect("read package");

    assert!(!package_bytes
        .windows(filename.len())
        .any(|window| window == filename.as_bytes()));
}

#[test]
fn receipt_time_is_local_output_only_and_not_package_metadata() {
    let temporary = TempDir::new().expect("temporary directory");
    let (_identity, recipient) = keygen(temporary.path(), "receipt-time");
    let input = temporary.path().join("input.txt");
    let package = temporary.path().join("bundle.pqsend");
    fs::write(&input, b"body").expect("write input");

    let pack_output = pack(&input, &recipient, &package);
    let pack_stdout = String::from_utf8_lossy(&pack_output.stdout);
    assert!(pack_stdout.contains("Local receipt time (Unix seconds; not package metadata): "));

    let package_bytes = fs::read(&package).expect("read package");
    assert!(!package_bytes
        .windows("Local receipt time".len())
        .any(|window| window == b"Local receipt time"));

    let mut command = pqsend();
    command.arg("inspect").arg(package);
    let inspect_output = success(command);
    assert!(!String::from_utf8_lossy(&inspect_output.stdout).contains("receipt time"));
}

#[test]
fn inspect_does_not_show_original_filename() {
    let temporary = TempDir::new().expect("temporary directory");
    let filename = "inspect-must-not-reveal-this.txt";
    let (_identity, _recipient, _input, package) =
        packaged_file(temporary.path(), "inspect-name", filename, b"body");
    let mut command = pqsend();
    command.arg("inspect").arg(package);

    let output = success(command);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("format: pqsend"));
    assert!(stdout.contains("format version: 1"));
    assert!(stdout.contains("package mode: single file"));
    assert!(!stdout.contains(filename));
}

#[test]
fn inspect_does_not_show_paths_or_key_material() {
    let temporary = TempDir::new().expect("temporary directory");
    let (identity, recipient, input, package) = packaged_file(
        temporary.path(),
        "inspect-private",
        "private-name.txt",
        b"body",
    );
    let identity_text = fs::read_to_string(identity).expect("read identity");
    let secret = identity_text
        .lines()
        .find(|line| line.starts_with("AGE-SECRET-KEY-"))
        .expect("identity key");
    let recipient_text = fs::read_to_string(recipient).expect("read recipient");
    let recipient_key = recipient_text
        .lines()
        .find(|line| line.starts_with("age1"))
        .expect("recipient key");
    let mut command = pqsend();
    command.arg("inspect").arg(&package);

    let output = success(command);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(!stdout.contains(&input.display().to_string()));
    assert!(!stdout.contains(&package.display().to_string()));
    assert!(!stdout.contains(secret));
    assert!(!stdout.contains(recipient_key));
}

#[test]
fn inspect_does_not_show_plaintext_file_hash() {
    let temporary = TempDir::new().expect("temporary directory");
    let contents = b"hash remains encrypted";
    let (_identity, _recipient, _input, package) =
        packaged_file(temporary.path(), "inspect-hash", "hash.txt", contents);
    let hash = format!("{:x}", Sha256::digest(contents));
    let mut command = pqsend();
    command.arg("inspect").arg(package);

    let output = success(command);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(!stdout.to_ascii_lowercase().contains("sha"));
    assert!(!stdout.contains(&hash));
}

#[test]
fn open_refuses_to_overwrite_existing_output_file() {
    let temporary = TempDir::new().expect("temporary directory");
    let (identity, _recipient, _input, package) =
        packaged_file(temporary.path(), "no-overwrite", "document.txt", b"new");
    let output_directory = temporary.path().join("opened");
    fs::create_dir(&output_directory).expect("create output directory");
    let output_file = output_directory.join("document.txt");
    fs::write(&output_file, b"existing").expect("write existing output");
    let mut command = pqsend();
    command
        .arg("open")
        .arg(package)
        .arg("--identity-file")
        .arg(identity)
        .arg("--out")
        .arg(output_directory);

    let output = failure(command);

    assert_eq!(
        fs::read(output_file).expect("read existing output"),
        b"existing"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to overwrite"));
}

#[test]
fn wrong_identity_fails() {
    let temporary = TempDir::new().expect("temporary directory");
    let (_identity, _recipient, _input, package) =
        packaged_file(temporary.path(), "right", "secret.txt", b"body");
    let (wrong_identity, _wrong_recipient) = keygen(temporary.path(), "wrong");
    let mut command = pqsend();
    command
        .arg("open")
        .arg(package)
        .arg("--identity-file")
        .arg(wrong_identity)
        .arg("--out")
        .arg(temporary.path().join("opened"));

    let output = failure(command);

    assert!(String::from_utf8_lossy(&output.stderr).contains("no matching age X25519 identity"));
}

#[test]
fn tampered_package_fails() {
    let temporary = TempDir::new().expect("temporary directory");
    let (identity, _recipient, _input, package) =
        packaged_file(temporary.path(), "tampered", "secret.txt", b"body");
    let mut package_bytes = fs::read(&package).expect("read package");
    *package_bytes.last_mut().expect("payload byte") ^= 1;
    fs::write(&package, package_bytes).expect("write tampered package");
    let output_directory = temporary.path().join("opened");
    let mut command = pqsend();
    command
        .arg("open")
        .arg(package)
        .arg("--identity-file")
        .arg(identity)
        .arg("--out")
        .arg(&output_directory);

    failure(command);

    assert!(!output_directory.exists());
    assert_no_temporary_files(temporary.path());
}

#[test]
fn invalid_recipient_file_fails() {
    let temporary = TempDir::new().expect("temporary directory");
    let input = temporary.path().join("input.txt");
    let recipient = temporary.path().join("recipient.txt");
    let package = temporary.path().join("bundle.pqsend");
    fs::write(&input, b"body").expect("write input");
    fs::write(&recipient, b"ssh-ed25519 unsupported\n").expect("write invalid recipient");
    let mut command = pqsend();
    command
        .arg("pack")
        .arg(input)
        .arg("--recipient-file")
        .arg(recipient)
        .arg("--out")
        .arg(&package);

    failure(command);

    assert!(!package.exists());
}

#[test]
fn recipient_file_rejects_private_key_material_in_a_comment() {
    let temporary = TempDir::new().expect("temporary directory");
    let (identity, recipient) = keygen(temporary.path(), "comment-secret");
    let input = temporary.path().join("input.txt");
    let package = temporary.path().join("bundle.pqsend");
    fs::write(&input, b"body").expect("write input");
    let identity_text = fs::read_to_string(identity).expect("read identity");
    let secret = identity_text
        .lines()
        .find(|line| line.starts_with("AGE-SECRET-KEY-"))
        .expect("generated secret");
    let mut recipient_text = fs::read_to_string(&recipient).expect("read recipient");
    recipient_text.push_str(&format!("# accidental secret: {secret}\n"));
    fs::write(&recipient, recipient_text).expect("write unsafe recipient");
    let mut command = pqsend();
    command
        .arg("pack")
        .arg(input)
        .arg("--recipient-file")
        .arg(recipient)
        .arg("--out")
        .arg(&package);

    let output = failure(command);

    assert!(!package.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("private key material"));
}

#[test]
fn invalid_identity_file_fails() {
    let temporary = TempDir::new().expect("temporary directory");
    let (_identity, _recipient, _input, package) =
        packaged_file(temporary.path(), "invalid-identity", "secret.txt", b"body");
    let identity = temporary.path().join("bad-identity.txt");
    fs::write(&identity, b"AGE-PLUGIN-UNSUPPORTED\n").expect("write invalid identity");
    let mut command = pqsend();
    command
        .arg("open")
        .arg(package)
        .arg("--identity-file")
        .arg(identity)
        .arg("--out")
        .arg(temporary.path().join("opened"));

    failure(command);
}

#[test]
fn input_file_larger_than_v01_limit_fails() {
    let temporary = TempDir::new().expect("temporary directory");
    let (_identity, recipient) = keygen(temporary.path(), "large");
    let input = temporary.path().join("large.bin");
    let package = temporary.path().join("bundle.pqsend");
    let file = File::create(&input).expect("create sparse input");
    file.set_len(u64::try_from(MAX_FILE_BYTES + 1).expect("limit fits u64"))
        .expect("set sparse input length");
    let mut command = pqsend();
    command
        .arg("pack")
        .arg(input)
        .arg("--recipient-file")
        .arg(recipient)
        .arg("--out")
        .arg(&package);

    let output = failure(command);

    assert!(!package.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("size limit"));
}

#[cfg(unix)]
#[test]
fn unsafe_input_basename_fails() {
    let temporary = TempDir::new().expect("temporary directory");
    let (_identity, recipient) = keygen(temporary.path(), "unsafe");
    let input = temporary.path().join("unsafe:name.txt");
    let package = temporary.path().join("bundle.pqsend");
    fs::write(&input, b"body").expect("write unsafe-name input");
    let mut command = pqsend();
    command
        .arg("pack")
        .arg(input)
        .arg("--recipient-file")
        .arg(recipient)
        .arg("--out")
        .arg(&package);

    let output = failure(command);

    assert!(!package.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid or unsafe inner filename"));
}

#[test]
fn directory_input_fails() {
    let temporary = TempDir::new().expect("temporary directory");
    let (_identity, recipient) = keygen(temporary.path(), "directory");
    let package = temporary.path().join("bundle.pqsend");
    let mut command = pqsend();
    command
        .arg("pack")
        .arg(temporary.path())
        .arg("--recipient-file")
        .arg(recipient)
        .arg("--out")
        .arg(&package);

    let output = failure(command);

    assert!(!package.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("regular file"));
}

#[test]
fn failed_decryption_leaves_no_final_plaintext_output_file() {
    let temporary = TempDir::new().expect("temporary directory");
    let (_identity, _recipient, _input, package) =
        packaged_file(temporary.path(), "failure-cleanup", "secret.txt", b"body");
    let (wrong_identity, _wrong_recipient) = keygen(temporary.path(), "unrelated");
    let output_directory = temporary.path().join("opened");
    let mut command = pqsend();
    command
        .arg("open")
        .arg(package)
        .arg("--identity-file")
        .arg(wrong_identity)
        .arg("--out")
        .arg(&output_directory);

    failure(command);

    assert!(!output_directory.join("secret.txt").exists());
    assert!(!output_directory.exists());
    assert_no_temporary_files(temporary.path());
}

#[test]
fn pack_refuses_to_overwrite_existing_package_file() {
    let temporary = TempDir::new().expect("temporary directory");
    let (_identity, recipient) = keygen(temporary.path(), "package-overwrite");
    let input = temporary.path().join("input.txt");
    let package = temporary.path().join("bundle.pqsend");
    fs::write(&input, b"body").expect("write input");
    fs::write(&package, b"existing").expect("write existing package");
    let mut command = pqsend();
    command
        .arg("pack")
        .arg(input)
        .arg("--recipient-file")
        .arg(recipient)
        .arg("--out")
        .arg(&package);

    failure(command);

    assert_eq!(
        fs::read(package).expect("read existing package"),
        b"existing"
    );
}

#[test]
fn open_refuses_output_path_that_is_not_a_directory() {
    let temporary = TempDir::new().expect("temporary directory");
    let (identity, _recipient, _input, package) =
        packaged_file(temporary.path(), "bad-output", "secret.txt", b"body");
    let output_path = temporary.path().join("not-a-directory");
    fs::write(&output_path, b"existing file").expect("write output-path file");
    let mut command = pqsend();
    command
        .arg("open")
        .arg(package)
        .arg("--identity-file")
        .arg(identity)
        .arg("--out")
        .arg(output_path);

    let output = failure(command);

    assert!(String::from_utf8_lossy(&output.stderr).contains("not a directory"));
}

#[cfg(unix)]
#[test]
fn open_rejects_symbolic_link_output_directory() {
    let temporary = TempDir::new().expect("temporary directory");
    let (identity, _recipient, _input, package) =
        packaged_file(temporary.path(), "symlink-output", "secret.txt", b"body");
    let real_output = temporary.path().join("real-output");
    let output_link = temporary.path().join("output-link");
    fs::create_dir(&real_output).expect("create real output directory");
    symlink(&real_output, &output_link).expect("create output symlink");
    let mut command = pqsend();
    command
        .arg("open")
        .arg(package)
        .arg("--identity-file")
        .arg(identity)
        .arg("--out")
        .arg(output_link);

    let output = failure(command);

    assert!(String::from_utf8_lossy(&output.stderr).contains("symbolic link"));
    assert!(!real_output.join("secret.txt").exists());
}

#[test]
fn pack_requires_explicit_output_path_and_creates_no_derived_filename() {
    let temporary = TempDir::new().expect("temporary directory");
    let (_identity, recipient) = keygen(temporary.path(), "explicit-output");
    let input = temporary.path().join("revealing-name.txt");
    fs::write(&input, b"body").expect("write input");
    let mut command = pqsend();
    command
        .arg("pack")
        .arg(&input)
        .arg("--recipient-file")
        .arg(recipient);

    failure(command);

    assert!(!temporary.path().join("revealing-name.txt.pqsend").exists());
    assert_no_temporary_files(temporary.path());
}
