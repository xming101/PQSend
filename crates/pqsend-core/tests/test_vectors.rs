use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use pqsend_core::{
    encrypt_to_recipient, open_package, AgeBackendError, AgeIdentity, AgeRecipient, PackageError,
    PublicEnvelope, BACKEND_AGE_V1_X25519, FORMAT_VERSION_V1, MODE_SINGLE_FILE,
    PUBLIC_ENVELOPE_LEN,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
struct Manifest {
    vector: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    file: String,
    category: String,
    purpose: String,
    expected_result: String,
    format_version: u16,
    mode: u8,
    backend: u8,
    test_identity_included: bool,
    expected_restored_filename: Option<String>,
    expected_plaintext_sha256: Option<String>,
    expected_failure_reason: Option<String>,
    vector_sha256: String,
}

fn vector_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors/v0-alpha")
}

fn load_manifest() -> Manifest {
    let text =
        fs::read_to_string(vector_root().join("manifest.toml")).expect("read vector manifest");
    toml::from_str(&text).expect("parse vector manifest")
}

fn load_vector(vector: &Vector) -> Vec<u8> {
    fs::read(vector_root().join(&vector.file)).expect("read vector bytes")
}

fn fixture_key(filename: &str) -> String {
    let text = fs::read_to_string(vector_root().join(filename)).expect("read fixture key");
    assert!(text.contains("PUBLIC TEST FIXTURE ONLY"));
    assert!(text.contains("NEVER USE FOR REAL SECRETS"));

    let lines = text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 1, "fixture key must contain exactly one key");
    lines[0].to_owned()
}

fn test_identity() -> AgeIdentity {
    fixture_key("test-identity.txt")
        .parse()
        .expect("parse test identity")
}

fn test_recipient() -> AgeRecipient {
    fixture_key("test-recipient.txt")
        .parse()
        .expect("parse test recipient")
}

fn package_from_inner(inner: &[u8]) -> Vec<u8> {
    let mut encrypted_payload = Vec::new();
    encrypt_to_recipient(&test_recipient(), inner, &mut encrypted_payload)
        .expect("encrypt inner vector");
    let envelope = PublicEnvelope::v1(encrypted_payload.len()).expect("encode vector envelope");
    let mut package = Vec::with_capacity(PUBLIC_ENVELOPE_LEN + encrypted_payload.len());
    package.extend_from_slice(&envelope.encode());
    package.extend_from_slice(&encrypted_payload);
    package
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn expected_error(reason: &str) -> PackageError {
    match reason {
        "InvalidMagic" => PackageError::InvalidMagic,
        "UnsupportedVersion" => PackageError::UnsupportedVersion,
        "UnsupportedMode" => PackageError::UnsupportedMode,
        "UnsupportedBackend" => PackageError::UnsupportedBackend,
        "InvalidEncryptedPayloadLength" => PackageError::InvalidEncryptedPayloadLength,
        "EncryptedPayloadTooLarge" => PackageError::EncryptedPayloadTooLarge,
        "PackageLengthMismatch" => PackageError::PackageLengthMismatch,
        "InvalidInnerMagic" => PackageError::InvalidInnerMagic,
        "InnerVersionMismatch" => PackageError::InnerVersionMismatch,
        "InvalidFilename" => PackageError::InvalidFilename,
        "InvalidInnerLength" => PackageError::InvalidInnerLength,
        "HashMismatch" => PackageError::HashMismatch,
        "Backend.InvalidCiphertext" => PackageError::Backend(AgeBackendError::InvalidCiphertext),
        _ => panic!("unknown expected failure reason: {reason}"),
    }
}

fn binary_files(directory: &Path) -> Vec<String> {
    let mut files = fs::read_dir(directory)
        .expect("read vector directory")
        .map(|entry| entry.expect("read vector entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension != "md"))
        .map(|path| {
            path.strip_prefix(vector_root())
                .expect("vector under root")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect::<Vec<_>>();
    files.sort();
    files
}

#[test]
fn manifest_covers_all_vectors_and_hashes() {
    let manifest = load_manifest();
    let mut names = HashSet::new();
    let mut files = HashSet::new();

    for vector in &manifest.vector {
        assert!(names.insert(vector.name.clone()), "duplicate vector name");
        assert!(files.insert(vector.file.clone()), "duplicate vector file");
        assert!(!vector.purpose.trim().is_empty());
        assert!(matches!(
            vector.category.as_str(),
            "public-envelope" | "inner-plaintext" | "end-to-end-package"
        ));
        assert!(matches!(
            vector.expected_result.as_str(),
            "accept" | "reject"
        ));
        assert_eq!(vector.format_version, FORMAT_VERSION_V1);
        assert_eq!(vector.mode, MODE_SINGLE_FILE);
        assert_eq!(vector.backend, BACKEND_AGE_V1_X25519);
        assert_eq!(sha256_hex(&load_vector(vector)), vector.vector_sha256);

        if vector.expected_result == "accept" && vector.category != "public-envelope" {
            assert!(vector.expected_restored_filename.is_some());
            assert!(vector.expected_plaintext_sha256.is_some());
            assert!(vector.expected_failure_reason.is_none());
        } else if vector.expected_result == "reject" {
            assert!(vector.expected_restored_filename.is_none());
            assert!(vector.expected_plaintext_sha256.is_none());
            assert!(vector.expected_failure_reason.is_some());
        }

        if vector.test_identity_included {
            assert!(vector.file.ends_with(".pqsend"));
        }
    }

    let mut documented = files.into_iter().collect::<Vec<_>>();
    documented.sort();
    let mut present = binary_files(&vector_root().join("valid"));
    present.extend(binary_files(&vector_root().join("invalid")));
    present.sort();
    assert_eq!(documented, present);
}

#[test]
fn public_envelope_vectors_match_reference_behavior() {
    for vector in load_manifest()
        .vector
        .iter()
        .filter(|vector| vector.category == "public-envelope" && vector.file.ends_with(".bin"))
    {
        let result = PublicEnvelope::decode(&load_vector(vector));
        if vector.expected_result == "accept" {
            let envelope = result.expect("valid public envelope vector");
            assert_eq!(envelope.version(), vector.format_version);
            assert_eq!(envelope.mode(), vector.mode);
            assert_eq!(envelope.backend(), vector.backend);
        } else {
            assert_eq!(
                result,
                Err(expected_error(
                    vector
                        .expected_failure_reason
                        .as_deref()
                        .expect("invalid vector failure reason")
                ))
            );
        }
    }
}

#[test]
fn inner_plaintext_vectors_match_reference_behavior() {
    let identity = test_identity();

    for vector in load_manifest()
        .vector
        .iter()
        .filter(|vector| vector.category == "inner-plaintext")
    {
        let result = open_package(&package_from_inner(&load_vector(vector)), &identity);
        if vector.expected_result == "accept" {
            let opened = result.expect("valid inner plaintext vector");
            assert_eq!(
                Some(opened.filename.as_str()),
                vector.expected_restored_filename.as_deref()
            );
            assert_eq!(
                sha256_hex(&opened.file_bytes),
                vector
                    .expected_plaintext_sha256
                    .as_deref()
                    .expect("valid vector plaintext hash")
            );
        } else {
            assert_eq!(
                result,
                Err(expected_error(
                    vector
                        .expected_failure_reason
                        .as_deref()
                        .expect("invalid vector failure reason")
                ))
            );
        }
    }
}

#[test]
fn encrypted_package_vectors_match_reference_behavior() {
    let identity = test_identity();

    for vector in load_manifest()
        .vector
        .iter()
        .filter(|vector| vector.file.ends_with(".pqsend"))
    {
        let bytes = load_vector(vector);
        let result = open_package(&bytes, &identity);
        if vector.expected_result == "accept" {
            let opened = result.expect("valid encrypted package vector");
            let filename = vector
                .expected_restored_filename
                .as_deref()
                .expect("valid vector filename");
            assert_eq!(opened.filename, filename);
            assert_eq!(
                sha256_hex(&opened.file_bytes),
                vector
                    .expected_plaintext_sha256
                    .as_deref()
                    .expect("valid vector plaintext hash")
            );
            assert!(!bytes
                .windows(filename.len())
                .any(|window| window == filename.as_bytes()));
        } else {
            assert_eq!(
                result,
                Err(expected_error(
                    vector
                        .expected_failure_reason
                        .as_deref()
                        .expect("invalid vector failure reason")
                ))
            );
        }
    }
}
