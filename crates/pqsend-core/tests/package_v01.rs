use std::panic::{catch_unwind, AssertUnwindSafe};

use age::secrecy::ExposeSecret;
use pqsend_core::package::envelope::MAGIC;
use pqsend_core::{
    create_package, decrypt_with_identity, encrypt_to_recipient, open_package, AgeBackendError,
    AgeIdentity, AgeRecipient, PackageError, PublicEnvelope, BACKEND_AGE_V1_X25519,
    FORMAT_VERSION_V1, MAX_ENCRYPTED_PAYLOAD_BYTES, MAX_FILENAME_BYTES, MAX_FILE_BYTES,
    MAX_INNER_METADATA_BYTES, MAX_INNER_PLAINTEXT_BYTES, MAX_PACKAGE_BYTES, MODE_SINGLE_FILE,
    PUBLIC_ENVELOPE_LEN,
};
use sha2::{Digest, Sha256};

const INNER_MAGIC: [u8; 8] = *b"PQSINNER";
const INNER_HEADER_LEN: usize = 54;

fn keypair() -> (AgeIdentity, AgeRecipient) {
    let (identity, recipient, _recipient_text) = keypair_with_recipient_text();
    (identity, recipient)
}

fn keypair_with_recipient_text() -> (AgeIdentity, AgeRecipient, String) {
    let identity = age::x25519::Identity::generate();
    let recipient_text = identity.to_public().to_string();
    let recipient = recipient_text
        .parse()
        .expect("parse generated test recipient");
    let identity = identity.to_string();
    let identity = identity
        .expose_secret()
        .parse()
        .expect("parse generated test identity");

    (identity, recipient, recipient_text)
}

fn encode_test_inner(filename: &str, file_bytes: &[u8]) -> Vec<u8> {
    let filename_bytes = filename.as_bytes();
    let filename_len = u16::try_from(filename_bytes.len()).expect("test filename length");
    let file_size = u64::try_from(file_bytes.len()).expect("test file size");
    let hash: [u8; 32] = Sha256::digest(file_bytes).into();

    let mut inner = Vec::with_capacity(INNER_HEADER_LEN + filename_bytes.len() + file_bytes.len());
    inner.extend_from_slice(&INNER_MAGIC);
    inner.extend_from_slice(&FORMAT_VERSION_V1.to_be_bytes());
    inner.push(MODE_SINGLE_FILE);
    inner.push(BACKEND_AGE_V1_X25519);
    inner.extend_from_slice(&filename_len.to_be_bytes());
    inner.extend_from_slice(&file_size.to_be_bytes());
    inner.extend_from_slice(&hash);
    inner.extend_from_slice(filename_bytes);
    inner.extend_from_slice(file_bytes);
    inner
}

fn package_from_inner(inner: &[u8], recipient: &AgeRecipient) -> Vec<u8> {
    let mut encrypted_payload = Vec::new();
    encrypt_to_recipient(recipient, inner, &mut encrypted_payload).expect("encrypt test inner");
    let envelope = PublicEnvelope::v1(encrypted_payload.len()).expect("encode test envelope");
    let mut package = Vec::with_capacity(PUBLIC_ENVELOPE_LEN + encrypted_payload.len());
    package.extend_from_slice(&envelope.encode());
    package.extend_from_slice(&encrypted_payload);
    package
}

fn valid_package() -> (AgeIdentity, AgeRecipient, Vec<u8>) {
    let (identity, recipient) = keypair();
    let package =
        create_package("document.txt", b"authenticated file body", &recipient).expect("package");
    (identity, recipient, package)
}

fn assert_invalid_filename(filename: &str) {
    let (_identity, recipient) = keypair();
    assert_eq!(
        create_package(filename, b"body", &recipient),
        Err(PackageError::InvalidFilename)
    );
}

#[test]
fn public_envelope_codec_is_deterministic_and_exactly_20_bytes() {
    let envelope = PublicEnvelope::v1(0x0001_0203).expect("valid envelope");
    let encoded = envelope.encode();

    assert_eq!(encoded.len(), PUBLIC_ENVELOPE_LEN);
    assert_eq!(
        encoded,
        [
            0x89, b'P', b'Q', b'S', b'E', b'N', b'D', b'\n', 0x00, 0x01, 0x01, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
        ]
    );
    assert_eq!(
        PublicEnvelope::decode(&encoded).expect("decode envelope"),
        envelope
    );
}

#[test]
fn inner_plaintext_codec_is_deterministic() {
    let (identity, recipient) = keypair();
    let file_bytes = b"body";
    let package = create_package("a.txt", file_bytes, &recipient).expect("create package");
    let encoded =
        decrypt_with_identity(&identity, &package[PUBLIC_ENVELOPE_LEN..]).expect("decrypt inner");
    let expected_hash: [u8; 32] = Sha256::digest(file_bytes).into();

    assert_eq!(&encoded[..8], &INNER_MAGIC);
    assert_eq!(&encoded[8..10], &FORMAT_VERSION_V1.to_be_bytes());
    assert_eq!(encoded[10], MODE_SINGLE_FILE);
    assert_eq!(encoded[11], BACKEND_AGE_V1_X25519);
    assert_eq!(&encoded[12..14], &5_u16.to_be_bytes());
    assert_eq!(&encoded[14..22], &4_u64.to_be_bytes());
    assert_eq!(&encoded[22..54], &expected_hash);
    assert_eq!(&encoded[54..59], b"a.txt");
    assert_eq!(&encoded[59..], file_bytes);

    let decoded = open_package(&package, &identity).expect("open package");
    assert_eq!(decoded.filename, "a.txt");
    assert_eq!(decoded.file_bytes, file_bytes);
    assert_eq!(decoded.file_size, 4);
    assert_eq!(decoded.sha256, expected_hash);
}

#[test]
fn constants_match_the_v01_limits() {
    assert_eq!(PUBLIC_ENVELOPE_LEN, 20);
    assert_eq!(MAX_FILENAME_BYTES, 255);
    assert_eq!(MAX_FILE_BYTES, 67_108_864);
    assert_eq!(MAX_INNER_METADATA_BYTES, 309);
    assert_eq!(MAX_INNER_PLAINTEXT_BYTES, 67_109_173);
    assert_eq!(MAX_ENCRYPTED_PAYLOAD_BYTES, 68_157_749);
    assert_eq!(MAX_PACKAGE_BYTES, 68_157_769);
    assert_eq!(
        INNER_HEADER_LEN + MAX_FILENAME_BYTES,
        MAX_INNER_METADATA_BYTES
    );
    assert_eq!(
        MAX_INNER_METADATA_BYTES + MAX_FILE_BYTES,
        MAX_INNER_PLAINTEXT_BYTES
    );
    assert_eq!(
        PUBLIC_ENVELOPE_LEN + MAX_ENCRYPTED_PAYLOAD_BYTES,
        MAX_PACKAGE_BYTES
    );
}

#[test]
fn round_trip_package_create_and_open_restores_filename_and_file() {
    let (identity, recipient) = keypair();
    let file_bytes = b"PQSend v0.1 package round trip";

    let package = create_package("report.txt", file_bytes, &recipient).expect("create package");
    let opened = open_package(&package, &identity).expect("open package");

    assert_eq!(opened.filename, "report.txt");
    assert_eq!(opened.file_bytes, file_bytes);
    assert_eq!(opened.file_size, file_bytes.len() as u64);
    let expected_hash: [u8; 32] = Sha256::digest(file_bytes).into();
    assert_eq!(opened.sha256, expected_hash);
}

#[test]
fn package_bytes_do_not_contain_original_filename() {
    let (_identity, recipient) = keypair();
    let filename = "private-original-filename-that-must-remain-encrypted.txt";

    let package = create_package(filename, b"body", &recipient).expect("create package");

    assert!(!package
        .windows(filename.len())
        .any(|window| window == filename.as_bytes()));
}

#[test]
fn public_package_bytes_do_not_contain_plaintext_sha256_hash() {
    let (_identity, recipient) = keypair();
    let file_bytes = b"hash must remain encrypted";
    let hash: [u8; 32] = Sha256::digest(file_bytes).into();

    let package = create_package("hash.txt", file_bytes, &recipient).expect("create package");

    assert!(!package.windows(hash.len()).any(|window| window == hash));
}

#[test]
fn package_bytes_do_not_contain_plaintext_file_body() {
    let (_identity, recipient) = keypair();
    let file_bytes = b"private-file-body-marker-6c0c6977-84b6-46b1-b3cf-07b6ca138c04";

    let package = create_package("body.bin", file_bytes, &recipient).expect("create package");

    assert!(!package
        .windows(file_bytes.len())
        .any(|window| window == file_bytes));
}

#[test]
fn package_bytes_do_not_contain_recipient_text() {
    let (_identity, recipient, recipient_text) = keypair_with_recipient_text();

    let package = create_package("recipient.txt", b"body", &recipient).expect("create package");

    assert!(!package
        .windows(recipient_text.len())
        .any(|window| window == recipient_text.as_bytes()));
}

#[test]
fn package_shorter_than_public_envelope_fails() {
    let (identity, _recipient) = keypair();
    let package = [0_u8; PUBLIC_ENVELOPE_LEN - 1];

    assert_eq!(
        open_package(&package, &identity),
        Err(PackageError::PackageTooShort)
    );
}

#[test]
fn bad_magic_fails() {
    let (identity, _recipient, mut package) = valid_package();
    package[0] ^= 1;

    assert_eq!(
        open_package(&package, &identity),
        Err(PackageError::InvalidMagic)
    );
}

#[test]
fn unsupported_and_zero_versions_fail() {
    let (identity, _recipient, package) = valid_package();
    for version in [0_u16, 2_u16] {
        let mut changed = package.clone();
        changed[8..10].copy_from_slice(&version.to_be_bytes());
        assert_eq!(
            open_package(&changed, &identity),
            Err(PackageError::UnsupportedVersion)
        );
    }
}

#[test]
fn unsupported_mode_fails() {
    let (identity, _recipient, mut package) = valid_package();
    package[10] = 2;

    assert_eq!(
        open_package(&package, &identity),
        Err(PackageError::UnsupportedMode)
    );
}

#[test]
fn unsupported_backend_fails() {
    let (identity, _recipient, mut package) = valid_package();
    package[11] = 2;

    assert_eq!(
        open_package(&package, &identity),
        Err(PackageError::UnsupportedBackend)
    );
}

#[test]
fn zero_encrypted_payload_length_fails() {
    let (identity, _recipient, mut package) = valid_package();
    package[12..20].fill(0);

    assert_eq!(
        open_package(&package, &identity),
        Err(PackageError::InvalidEncryptedPayloadLength)
    );
}

#[test]
fn declared_payload_length_above_cap_fails() {
    let (identity, _recipient, mut package) = valid_package();
    let too_large = u64::try_from(MAX_ENCRYPTED_PAYLOAD_BYTES)
        .expect("limit fits u64")
        .checked_add(1)
        .expect("test length");
    package[12..20].copy_from_slice(&too_large.to_be_bytes());

    assert_eq!(
        open_package(&package, &identity),
        Err(PackageError::EncryptedPayloadTooLarge)
    );
}

#[test]
fn declared_package_length_mismatch_fails() {
    let (identity, _recipient, mut package) = valid_package();
    let declared = u64::from_be_bytes(package[12..20].try_into().expect("payload length"));
    package[12..20].copy_from_slice(&(declared - 1).to_be_bytes());

    assert_eq!(
        open_package(&package, &identity),
        Err(PackageError::PackageLengthMismatch)
    );
}

#[test]
fn trailing_outer_bytes_fail() {
    let (identity, _recipient, mut package) = valid_package();
    package.push(0);

    assert_eq!(
        open_package(&package, &identity),
        Err(PackageError::PackageLengthMismatch)
    );
}

#[test]
fn trailing_bytes_inside_declared_age_payload_fail() {
    let (identity, _recipient, mut package) = valid_package();
    package.push(0);
    let declared = u64::from_be_bytes(package[12..20].try_into().expect("payload length"));
    package[12..20].copy_from_slice(&(declared + 1).to_be_bytes());

    assert_eq!(
        open_package(&package, &identity),
        Err(PackageError::Backend(AgeBackendError::InvalidCiphertext))
    );
}

#[test]
fn concatenated_complete_age_payloads_fail() {
    let (identity, recipient, mut package) = valid_package();
    let second_package =
        create_package("second.txt", b"second body", &recipient).expect("create second package");
    package.extend_from_slice(&second_package[PUBLIC_ENVELOPE_LEN..]);
    let combined_payload_len =
        u64::try_from(package.len() - PUBLIC_ENVELOPE_LEN).expect("combined payload length");
    package[12..20].copy_from_slice(&combined_payload_len.to_be_bytes());

    assert_eq!(
        open_package(&package, &identity),
        Err(PackageError::Backend(AgeBackendError::InvalidCiphertext))
    );
}

#[test]
fn tampered_encrypted_payload_fails() {
    let (identity, _recipient, mut package) = valid_package();
    *package.last_mut().expect("payload byte") ^= 1;

    assert_eq!(
        open_package(&package, &identity),
        Err(PackageError::Backend(AgeBackendError::InvalidCiphertext))
    );
}

#[test]
fn truncated_package_fails() {
    let (identity, _recipient, mut package) = valid_package();
    package.pop();

    assert_eq!(
        open_package(&package, &identity),
        Err(PackageError::PackageLengthMismatch)
    );
}

#[test]
fn wrong_identity_fails_without_returning_plaintext() {
    let (_identity, _recipient, package) = valid_package();
    let (wrong_identity, _wrong_recipient) = keypair();

    assert_eq!(
        open_package(&package, &wrong_identity),
        Err(PackageError::Backend(AgeBackendError::NoMatchingIdentity))
    );
}

#[test]
fn bad_inner_magic_fails() {
    let (identity, recipient) = keypair();
    let mut inner = encode_test_inner("a.txt", b"body");
    inner[0] ^= 1;

    assert_eq!(
        open_package(&package_from_inner(&inner, &recipient), &identity),
        Err(PackageError::InvalidInnerMagic)
    );
}

#[test]
fn short_inner_header_fails() {
    let (identity, recipient) = keypair();

    assert_eq!(
        open_package(&package_from_inner(b"short", &recipient), &identity),
        Err(PackageError::InnerHeaderTooShort)
    );
}

#[test]
fn inner_public_version_mismatch_fails() {
    let (identity, recipient) = keypair();
    let mut inner = encode_test_inner("a.txt", b"body");
    inner[8..10].copy_from_slice(&2_u16.to_be_bytes());

    assert_eq!(
        open_package(&package_from_inner(&inner, &recipient), &identity),
        Err(PackageError::InnerVersionMismatch)
    );
}

#[test]
fn inner_public_mode_mismatch_fails() {
    let (identity, recipient) = keypair();
    let mut inner = encode_test_inner("a.txt", b"body");
    inner[10] = 2;

    assert_eq!(
        open_package(&package_from_inner(&inner, &recipient), &identity),
        Err(PackageError::InnerModeMismatch)
    );
}

#[test]
fn inner_public_backend_mismatch_fails() {
    let (identity, recipient) = keypair();
    let mut inner = encode_test_inner("a.txt", b"body");
    inner[11] = 2;

    assert_eq!(
        open_package(&package_from_inner(&inner, &recipient), &identity),
        Err(PackageError::InnerBackendMismatch)
    );
}

#[test]
fn sha256_mismatch_fails() {
    let (identity, recipient) = keypair();
    let mut inner = encode_test_inner("a.txt", b"body");
    inner[22] ^= 1;

    assert_eq!(
        open_package(&package_from_inner(&inner, &recipient), &identity),
        Err(PackageError::HashMismatch)
    );
}

#[test]
fn package_errors_do_not_include_decrypted_filename_or_file_contents() {
    let (identity, recipient) = keypair();
    let filename = "private-decrypted-filename-marker.txt";
    let file_bytes = b"private-decrypted-file-contents-marker";
    let mut inner = encode_test_inner(filename, file_bytes);
    inner[22] ^= 1;

    let error = open_package(&package_from_inner(&inner, &recipient), &identity)
        .expect_err("hash mismatch must fail");
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(!rendered.contains(filename));
        assert!(!rendered.contains(std::str::from_utf8(file_bytes).expect("test body is UTF-8")));
    }
}

#[test]
fn file_size_mismatch_fails() {
    let (identity, recipient) = keypair();
    let mut inner = encode_test_inner("a.txt", b"body");
    inner[14..22].copy_from_slice(&5_u64.to_be_bytes());

    assert_eq!(
        open_package(&package_from_inner(&inner, &recipient), &identity),
        Err(PackageError::InvalidInnerLength)
    );
}

#[test]
fn file_size_above_cap_fails() {
    let (identity, recipient) = keypair();
    let mut inner = encode_test_inner("a.txt", b"body");
    let too_large = u64::try_from(MAX_FILE_BYTES + 1).expect("test size fits u64");
    inner[14..22].copy_from_slice(&too_large.to_be_bytes());

    assert_eq!(
        open_package(&package_from_inner(&inner, &recipient), &identity),
        Err(PackageError::FileTooLarge)
    );
}

#[test]
fn trailing_inner_bytes_fail() {
    let (identity, recipient) = keypair();
    let mut inner = encode_test_inner("a.txt", b"body");
    inner.push(0);

    assert_eq!(
        open_package(&package_from_inner(&inner, &recipient), &identity),
        Err(PackageError::InvalidInnerLength)
    );
}

#[test]
fn empty_file_works() {
    let (identity, recipient) = keypair();
    let package = create_package("empty.txt", b"", &recipient).expect("create empty package");
    let opened = open_package(&package, &identity).expect("open empty package");

    assert!(opened.file_bytes.is_empty());
    assert_eq!(opened.file_size, 0);
}

#[test]
fn file_larger_than_64_kib_works() {
    let (identity, recipient) = keypair();
    let file_bytes = (0..(128 * 1024 + 37))
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let package = create_package("large.bin", &file_bytes, &recipient).expect("create package");
    let opened = open_package(&package, &identity).expect("open package");

    assert_eq!(opened.file_bytes, file_bytes);
}

#[test]
fn package_round_trip_accepts_file_exactly_at_maximum_size() {
    let (identity, recipient) = keypair();
    let file_bytes = vec![0_u8; MAX_FILE_BYTES];
    let package =
        create_package("max.bin", &file_bytes, &recipient).expect("create maximum package");
    let opened = open_package(&package, &identity).expect("open maximum package");

    assert_eq!(opened.filename, "max.bin");
    assert_eq!(opened.file_size, MAX_FILE_BYTES as u64);
    assert_eq!(opened.file_bytes, file_bytes);
}

#[test]
fn file_above_maximum_size_fails() {
    let (_identity, recipient) = keypair();
    let file_bytes = vec![0_u8; MAX_FILE_BYTES + 1];

    assert_eq!(
        create_package("too-large.bin", &file_bytes, &recipient),
        Err(PackageError::FileTooLarge)
    );
}

#[test]
fn empty_filename_fails_through_public_package_api() {
    assert_invalid_filename("");
}

#[test]
fn inner_filename_length_zero_fails() {
    let (identity, recipient) = keypair();
    let mut inner = encode_test_inner("a", b"body");
    inner[12..14].fill(0);

    assert_eq!(
        open_package(&package_from_inner(&inner, &recipient), &identity),
        Err(PackageError::InvalidFilename)
    );
}

#[test]
fn filename_length_255_works() {
    let (identity, recipient) = keypair();
    let filename = "a".repeat(MAX_FILENAME_BYTES);
    let package = create_package(&filename, b"body", &recipient).expect("create package");
    let opened = open_package(&package, &identity).expect("open package");

    assert_eq!(opened.filename, filename);
}

#[test]
fn filename_length_256_fails() {
    assert_invalid_filename(&"a".repeat(MAX_FILENAME_BYTES + 1));
}

#[test]
fn inner_filename_length_above_255_fails() {
    let (identity, recipient) = keypair();
    let mut inner = encode_test_inner("a", b"body");
    inner[12..14].copy_from_slice(&256_u16.to_be_bytes());

    assert_eq!(
        open_package(&package_from_inner(&inner, &recipient), &identity),
        Err(PackageError::InvalidFilename)
    );
}

#[test]
fn filename_containing_forward_slash_fails() {
    assert_invalid_filename("directory/file.txt");
}

#[test]
fn filename_containing_backslash_fails() {
    assert_invalid_filename(r"directory\file.txt");
}

#[test]
fn dot_filename_fails() {
    assert_invalid_filename(".");
}

#[test]
fn dot_dot_filename_fails() {
    assert_invalid_filename("..");
}

#[test]
fn filename_containing_nul_fails() {
    assert_invalid_filename("nul\0byte.txt");
}

#[test]
fn filename_containing_ascii_control_character_fails() {
    assert_invalid_filename("line\nbreak.txt");
    assert_invalid_filename("delete\u{7f}.txt");
}

#[test]
fn filename_containing_windows_forbidden_character_fails() {
    for forbidden in ['<', '>', ':', '"', '|', '?', '*'] {
        assert_invalid_filename(&format!("bad{forbidden}name.txt"));
    }
}

#[test]
fn filename_ending_in_dot_fails() {
    assert_invalid_filename("name.");
}

#[test]
fn filename_ending_in_space_fails() {
    assert_invalid_filename("name ");
}

#[test]
fn reserved_windows_device_filename_fails_case_insensitively() {
    for filename in [
        "CON",
        "prn",
        "Aux.txt",
        "nul",
        "COM1",
        "com9.log",
        "LPT1",
        "lpt9.txt",
        "COM¹",
        "com².log",
        "COM³",
        "LPT¹",
        "lpt².txt",
        "LPT³",
    ] {
        assert_invalid_filename(filename);
    }
}

#[test]
fn non_utf8_inner_filename_fails() {
    let (identity, recipient) = keypair();
    let mut inner = encode_test_inner("a", b"body");
    inner[INNER_HEADER_LEN] = 0xff;

    assert_eq!(
        open_package(&package_from_inner(&inner, &recipient), &identity),
        Err(PackageError::InvalidFilename)
    );
}

#[test]
fn valid_non_ascii_filename_is_accepted() {
    let (identity, recipient) = keypair();
    let package = create_package("aaé", b"body", &recipient).expect("create package");

    assert_eq!(
        open_package(&package, &identity)
            .expect("open package")
            .filename,
        "aaé"
    );
}

#[test]
fn malformed_outer_inputs_do_not_panic() {
    let (identity, _recipient) = keypair();

    for len in 0..=(PUBLIC_ENVELOPE_LEN + 64) {
        let bytes = (0..len)
            .map(|index| index.wrapping_mul(37) as u8)
            .collect::<Vec<_>>();
        let result = catch_unwind(AssertUnwindSafe(|| open_package(&bytes, &identity)));

        assert!(result.is_ok(), "outer input length {len} panicked");
        assert!(
            result.expect("checked above").is_err(),
            "malformed outer input length {len} was accepted"
        );
    }
}

#[test]
fn malformed_authenticated_inner_inputs_do_not_panic() {
    let (identity, recipient) = keypair();

    for len in 0..=(INNER_HEADER_LEN + 16) {
        let inner = (0..len)
            .map(|index| index.wrapping_mul(53) as u8)
            .collect::<Vec<_>>();
        let package = package_from_inner(&inner, &recipient);
        let result = catch_unwind(AssertUnwindSafe(|| open_package(&package, &identity)));

        assert!(result.is_ok(), "inner input length {len} panicked");
        assert!(
            result.expect("checked above").is_err(),
            "malformed inner input length {len} was accepted"
        );
    }
}

#[test]
fn public_envelope_contains_only_the_selected_fields() {
    let envelope = PublicEnvelope::v1(42).expect("envelope").encode();

    assert_eq!(&envelope[..8], &MAGIC);
    assert_eq!(&envelope[8..10], &FORMAT_VERSION_V1.to_be_bytes());
    assert_eq!(envelope[10], MODE_SINGLE_FILE);
    assert_eq!(envelope[11], BACKEND_AGE_V1_X25519);
    assert_eq!(&envelope[12..20], &42_u64.to_be_bytes());
}
