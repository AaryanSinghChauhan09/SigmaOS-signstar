//! Integration tests for the Signstar signing protocol implementation.

use std::io::Write;

use semver::Version;
use sha2::{Digest, Sha512};
use signstar::{
    BackendType, CertificateType, HashType, Host, LocalFileSigner, Request, RequestError,
    Response, SignatureType, config::ConfigResolver,
};

/// Arrange: write `contents` to a temp file and build a signing request.
fn request_for(contents: &[u8]) -> (tempfile::TempDir, Request) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("artifact.bin");
    std::fs::write(&path, contents).unwrap();
    let request = Request::for_file(&path).unwrap();
    (dir, request)
}

#[test]
fn test_for_file_produces_valid_v1_request() {
    // Arrange & Act
    let (_dir, request) = request_for(b"sigmaos signing test payload");

    // Assert
    assert_eq!(request.version, Version::new(1, 0, 0));
    assert!(request.required.output.is_openpgp_v4());
    assert_eq!(
        request.required.input.hash_type,
        HashType::Sha2_0_11_Sha512_State
    );
    assert!(request.validate().is_ok());
    // Optional parameters must contain request-time and file-name.
    assert!(request.optional.contains_key("request-time"));
    assert_eq!(
        request.optional.get("file-name").unwrap(),
        &serde_json::Value::String("artifact.bin".to_string())
    );
}

#[test]
fn test_for_file_hash_matches_payload_digest() {
    // Arrange
    let payload = b"the quick brown fox jumps over the lazy dog";
    let (_dir, request) = request_for(payload);

    // Act: deserialize the hasher state carried by the request.
    let hasher: Sha512 = request.required.input.clone().try_into().unwrap();
    let digest = hasher.finalize();

    // Assert: digest equals a direct SHA-512 of the payload.
    let expected = Sha512::digest(payload);
    assert_eq!(digest.as_slice(), expected.as_slice());
}

#[test]
fn test_request_json_roundtrip() {
    // Arrange
    let (_dir, request) = request_for(b"roundtrip");

    // Act
    let json = request.to_json().unwrap();
    let parsed = Request::from_json(&json).unwrap();

    // Assert
    assert_eq!(parsed.version, request.version);
    assert!(parsed.validate().is_ok());
}

#[test]
fn test_response_roundtrip_and_signature_writer() {
    // Arrange
    let response = Response::v1("c2lnbmF0dXJl".to_string());

    // Act
    let mut buf = Vec::new();
    response.to_writer(&mut buf).unwrap();
    let parsed = Response::from_reader(buf.as_slice()).unwrap();
    let mut sig = Vec::new();
    parsed.signature_to_writer(&mut sig).unwrap();

    // Assert
    assert_eq!(sig, b"c2lnbmF0dXJl");
    assert_eq!(parsed.version, Version::new(1, 0, 0));
}

#[test]
fn test_host_signs_valid_request_end_to_end() {
    // Arrange
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("signing.key");
    std::fs::write(&key_path, b"sigmaos-test-hmac-key").unwrap();
    let host = Host::new(LocalFileSigner::new(&key_path));

    let (_dir2, request) = request_for(b"please sign me");

    // Act
    let response = host.handle_request(&request).unwrap();

    // Assert: signature is non-empty base64 and deterministic for same input.
    assert!(!response.signature().is_empty());
    let response2 = host.handle_request(&request).unwrap();
    assert_eq!(response.signature(), response2.signature());
}

#[test]
fn test_host_handle_json_roundtrip() {
    // Arrange
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("k");
    std::fs::write(&key_path, b"key-material").unwrap();
    let host = Host::new(LocalFileSigner::new(&key_path));
    let (_d, request) = request_for(b"json path");
    let json = request.to_json().unwrap();

    // Act
    let out = host.handle_json(&json).unwrap();
    let response = Response::from_reader(out.as_slice()).unwrap();

    // Assert
    assert!(!response.signature().is_empty());
}

#[test]
fn test_host_rejects_unsupported_version() {
    // Arrange
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("k");
    std::fs::write(&key_path, b"k").unwrap();
    let host = Host::new(LocalFileSigner::new(&key_path));
    let (_d, mut request) = request_for(b"x");
    request.version = Version::new(2, 0, 0);

    // Act & Assert
    assert!(host.handle_request(&request).is_err());
}

#[test]
fn test_host_rejects_malformed_json() {
    // Arrange
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("k");
    std::fs::write(&key_path, b"k").unwrap();
    let host = Host::new(LocalFileSigner::new(&key_path));

    // Act & Assert
    assert!(host.handle_json(b"{not json").is_err());
}

#[test]
fn test_unknown_optional_parameters_are_ignored() {
    // Arrange: inject arbitrary optional params; the host must ignore them.
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("k");
    std::fs::write(&key_path, b"k").unwrap();
    let host = Host::new(LocalFileSigner::new(&key_path));
    let (_d, mut request) = request_for(b"grease test");
    request
        .optional
        .insert("future-extension".into(), serde_json::json!({"nested": [1, 2, 3]}));

    // Act & Assert
    assert!(host.handle_request(&request).is_ok());
}

#[test]
fn test_certificate_framing_is_armored_openpgp() {
    // Arrange
    let raw = b"fake-cert-bytes";

    // Act
    let framed = CertificateType::OpenPgp.with_framing(raw).to_string();

    // Assert
    assert!(framed.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    assert!(framed.ends_with("-----END PGP PUBLIC KEY BLOCK-----"));
    assert!(framed.contains(&base64_encode(raw)));
}

fn base64_encode(data: &[u8]) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(TBL[(n >> 18) as usize & 63] as char);
        out.push(TBL[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { TBL[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { TBL[n as usize & 63] as char } else { '=' });
    }
    out
}

#[test]
fn test_config_resolver_precedence() {
    // Arrange: build a scratch hierarchy with config.toml in two dirs.
    let root = tempfile::tempdir().unwrap();
    let resolver = ConfigResolver::new(root.path());

    // Act & Assert: nothing exists yet -> falls back to lowest-precedence path.
    assert!(resolver.config_file().is_none());
    let fallback = resolver.config_file_or_default();
    assert!(fallback.ends_with("usr/share/signstar/config.toml"));

    // Place a file in the default dir, then a higher-precedence one.
    let default_dir = root.path().join("usr/share/signstar");
    std::fs::create_dir_all(&default_dir).unwrap();
    std::fs::write(default_dir.join("config.toml"), b"[host]\n").unwrap();
    assert!(resolver.config_file().unwrap().starts_with(&default_dir));

    let etc_dir = root.path().join("etc/signstar");
    std::fs::create_dir_all(&etc_dir).unwrap();
    std::fs::write(etc_dir.join("config.toml"), b"[host]\n").unwrap();
    assert!(resolver.config_file().unwrap().starts_with(&etc_dir));
}

#[test]
fn test_backend_type_display() {
    assert_eq!(BackendType::NetHSM.to_string(), "NetHSM");
    assert_eq!(BackendType::YubiHSM2.to_string(), "YubiHSM2");
}

#[test]
fn test_for_file_missing_file_errors() {
    // Act & Assert
    assert!(Request::for_file("/nonexistent/sigmaos-missing-file").is_err());
}

#[test]
fn test_signature_type_serializes_as_upstream() {
    // Arrange & Act
    let json = serde_json::to_string(&SignatureType::OpenPgpV4).unwrap();

    // Assert: matches upstream wire format.
    assert_eq!(json, "\"OpenPGPv4\"");
}

#[test]
fn test_hash_type_serializes_as_upstream() {
    // Arrange & Act
    let json = serde_json::to_string(&HashType::Sha2_0_11_Sha512_State).unwrap();

    // Assert: matches upstream wire format.
    assert_eq!(json, "\"sha2-0.11-SHA512-state\"");
}

#[test]
fn test_empty_optional_map_accepted() {
    // Arrange: minimal valid request without optional fields.
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("k");
    std::fs::write(&key_path, b"k").unwrap();
    let host = Host::new(LocalFileSigner::new(&key_path));

    let mut hasher = Sha512::new();
    hasher.update(b"payload");
    let request = Request {
        version: Version::new(1, 0, 0),
        required: signstar::Required {
            input: signstar::SignatureRequestInput::from(hasher),
            output: signstar::SignatureRequestOutput::new_openpgp_v4(),
        },
        optional: Default::default(),
    };

    // Act & Assert
    assert!(host.handle_request(&request).is_ok());
}

#[test]
fn test_response_signature_writer_io_error() {
    // Arrange: a writer that always fails.
    struct FailingWriter;
    impl std::io::Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "boom"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut w = FailingWriter;
    let response = Response::v1("sig".to_string());

    // Act & Assert
    assert!(response.signature_to_writer(&mut w).is_err());
}

#[test]
fn test_request_error_display() {
    // Arrange
    let err = RequestError::RequiredParameterNotUnderstood("x".into());

    // Act & Assert
    assert!(err.to_string().contains("required parameter"));
}
