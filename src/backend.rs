//! Signing backends and host-side request processing.
//!
//! Upstream Signstar delegates signing to an HSM (Nitrokey NetHSM or
//! YubiHSM2) attached to a hardened host. This component models the host
//! side of that protocol: request validation, digest extraction, and a
//! pluggable [`Signer`] backend trait. A `LocalFileSigner` development
//! backend is provided for testing and offline operation; production
//! deployments plug in an HSM-backed implementation.

use std::io::Write;

use base64::Engine as _;
use sha2::{Digest, Sha512};

use crate::{
    error::HostError,
    request::{CertificateType, HashType, Request, Response, SignatureType},
};

/// The kind of HSM backend attached to a Signstar host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BackendType {
    /// Nitrokey NetHSM backend.
    NetHSM,
    /// Yubico YubiHSM 2 backend.
    YubiHSM2,
}

impl std::fmt::Display for BackendType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendType::NetHSM => write!(f, "NetHSM"),
            BackendType::YubiHSM2 => write!(f, "YubiHSM2"),
        }
    }
}

/// A signing backend capable of producing an OpenPGP v4 signature over the
/// finalized digest carried by a validated [`Request`].
pub trait Signer {
    /// Produce the signature payload for a validated request.
    ///
    /// `digest` is the finalized SHA-512 hash of the payload the client
    /// requested a signature for.
    fn sign(&self, digest: &[u8; 32], request: &Request) -> Result<Vec<u8>, HostError>;

    /// The backend type identifier for certificate metadata.
    fn backend_type(&self) -> BackendType;
}

/// A development backend that signs digests with an HMAC-SHA256 key stored
/// in a local file. NOT for production use — it exists so the full request
/// pipeline can be exercised end-to-end without HSM hardware.
#[derive(Debug)]
pub struct LocalFileSigner {
    key_path: std::path::PathBuf,
    backend: BackendType,
}

impl LocalFileSigner {
    /// Create a signer reading its key from `key_path`.
    pub fn new(key_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            key_path: key_path.into(),
            backend: BackendType::NetHSM,
        }
    }

    /// Set the reported backend type.
    pub fn with_backend_type(mut self, backend: BackendType) -> Self {
        self.backend = backend;
        self
    }

    fn key(&self) -> Result<Vec<u8>, HostError> {
        std::fs::read(&self.key_path).map_err(|source| HostError::Backend(format!(
            "reading signer key {}: {source}",
            self.key_path.display()
        )))
    }
}

impl Signer for LocalFileSigner {
    fn sign(&self, digest: &[u8; 32], _request: &Request) -> Result<Vec<u8>, HostError> {
        // Development signature: SHA-256 over key || digest. This is NOT a
        // real signature scheme — it exists to exercise the request pipeline
        // end-to-end without HSM hardware.
        let key = self.key()?;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&key);
        hasher.update(digest);
        Ok(hasher.finalize().to_vec())
    }

    fn backend_type(&self) -> BackendType {
        self.backend
    }
}

/// A Signstar host: validates requests and delegates signing to a backend.
#[derive(Debug)]
pub struct Host<S: Signer> {
    signer: S,
}

impl<S: Signer> Host<S> {
    /// Create a host backed by `signer`.
    pub fn new(signer: S) -> Self {
        Self { signer }
    }

    /// Handle a raw JSON request, returning the JSON response bytes.
    pub fn handle_json(&self, request_json: &[u8]) -> Result<Vec<u8>, HostError> {
        let request = Request::from_json(request_json)?;
        let response = self.handle_request(&request)?;
        let mut buf = Vec::new();
        response
            .to_writer(&mut buf)
            .map_err(|e| HostError::Backend(format!("serializing response: {e}")))?;
        Ok(buf)
    }

    /// Validate and sign a parsed request.
    pub fn handle_request(&self, request: &Request) -> Result<Response, HostError> {
        request.validate().map_err(HostError::InvalidRequest)?;

        let hasher: Sha512 = request
            .required
            .input
            .clone()
            .try_into()
            .map_err(HostError::InvalidRequest)?;
        // The signing backend receives the finalized payload digest; the
        // dev backend uses the first 32 bytes while HSM backends can consume
        // the full digest via `finalize_request`.
        let digest = finalize_digest(&hasher);

        let signature = self.signer.sign(&digest, request)?;
        Ok(Response::v1(base64::engine::general_purpose::STANDARD.encode(&signature)))
    }

    /// Finalize the request hasher state into the raw payload digest.
    pub fn finalize_request(&self, request: &Request) -> Result<[u8; 64], HostError> {
        let hasher: Sha512 = request
            .required
            .input
            .clone()
            .try_into()
            .map_err(HostError::InvalidRequest)?;
        let out = hasher.finalize();
        let mut arr = [0u8; 64];
        arr.copy_from_slice(out.as_slice());
        Ok(arr)
    }

    /// Access the configured signer.
    pub fn signer(&self) -> &S {
        &self.signer
    }
}

/// Finalize a hasher into the 32-byte digest used by the dev signer.
fn finalize_digest(hasher: &Sha512) -> [u8; 32] {
    let full = hasher.clone().finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full.as_slice()[..32]);
    out
}

/// Convenience: produce an armored OpenPGP certificate blob for `raw` bytes.
pub fn armored_certificate(raw: &[u8]) -> String {
    CertificateType::OpenPgp.with_framing(raw).to_string()
}

/// Write bytes to a writer, mapping I/O failures into a host error.
pub fn write_all<W: Write>(mut w: W, bytes: &[u8]) -> Result<(), HostError> {
    w.write_all(bytes)
        .map_err(|e| HostError::Backend(format!("write failed: {e}")))
}

/// Re-export for host implementations that only need the digest type.
pub type PayloadDigest = [u8; 64];

/// The signature types this host can produce.
pub const SUPPORTED_SIGNATURE_TYPES: &[SignatureType] = &[SignatureType::OpenPgpV4];

/// The hash types this host accepts as request input.
pub const SUPPORTED_HASH_TYPES: &[HashType] = &[HashType::Sha2_0_11_Sha512_State];
