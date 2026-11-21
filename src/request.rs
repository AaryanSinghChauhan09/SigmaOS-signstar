//! Signstar signing request/response protocol types.
//!
//! Ported from `archlinux/signstar` `signstar-common::request_api`, which
//! implements the protocol documented at
//! <https://signstar.archlinux.page/signing-api/request.html> and
//! <https://signstar.archlinux.page/signing-api/response.html>.

use std::{
    collections::HashMap,
    fmt::Display,
    fs::File,
    io::{Read, Write},
    path::Path,
    time::SystemTime,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::Rng;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::{Value, from_reader, to_writer};
use sha2::{Digest, Sha512, digest::common::hazmat::SerializableState};

use crate::{backend::BackendType, error::RequestError};

/// Signature request processing error alias kept for API clarity.
pub type Error = RequestError;

/// Type of the input hash carried by a signing request.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HashType {
    /// Serialized state of the SHA-512 hasher as understood by `sha2`.
    #[serde(rename = "sha2-0.11-SHA512-state")]
    #[expect(
        non_camel_case_types,
        reason = "Rust suggested casing is unreadable"
    )]
    Sha2_0_11_Sha512_State,
}

/// The requested signature type.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub enum SignatureType {
    /// OpenPGP signature (version 4).
    #[serde(rename = "OpenPGPv4")]
    OpenPgpV4,
}

/// Input of the signing request process: a serialized hasher state.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignatureRequestInput {
    /// Hash type discriminator, serialized as `type`.
    #[serde(rename = "type")]
    pub hash_type: HashType,
    /// Serialized hasher state bytes.
    pub content: Vec<u8>,
}

impl From<Sha512> for SignatureRequestInput {
    fn from(value: Sha512) -> Self {
        Self {
            hash_type: HashType::Sha2_0_11_Sha512_State,
            content: value.serialize().to_vec(),
        }
    }
}

impl TryFrom<SignatureRequestInput> for Sha512 {
    type Error = RequestError;

    fn try_from(value: SignatureRequestInput) -> Result<Self, Self::Error> {
        if value.hash_type != HashType::Sha2_0_11_Sha512_State {
            return Err(RequestError::InvalidContentType {
                actual: value.hash_type,
                expected: HashType::Sha2_0_11_Sha512_State,
            });
        }

        Ok(Sha512::deserialize(
            value.content[..]
                .try_into()
                .map_err(|source| RequestError::HasherMisalignedSize {
                    size: value.content.len(),
                    source,
                })?,
        )
        .map_err(RequestError::HasherDeserialization)?)
    }
}

/// Outputs of the signing process.
#[derive(Debug, Deserialize, Serialize)]
pub struct SignatureRequestOutput {
    /// Type of the signature to be produced, serialized as `type`.
    #[serde(rename = "type")]
    pub sig_type: SignatureType,
}

impl SignatureRequestOutput {
    /// Create a new signature output which asks for an OpenPGP v4 signature.
    pub fn new_openpgp_v4() -> Self {
        Self {
            sig_type: SignatureType::OpenPgpV4,
        }
    }

    /// Whether this output asks for an OpenPGP v4 signature.
    pub fn is_openpgp_v4(&self) -> bool {
        self.sig_type == SignatureType::OpenPgpV4
    }
}

/// Required parameters for the signing request operation.
#[derive(Debug, Deserialize, Serialize)]
pub struct Required {
    /// Inputs of the signing procedure.
    pub input: SignatureRequestInput,
    /// Outputs of the signing procedure.
    pub output: SignatureRequestOutput,
}

/// Signing request as exchanged between `signstar-client` and a Signstar host.
#[derive(Debug, Deserialize, Serialize)]
pub struct Request {
    /// Version of this signing request.
    pub version: Version,
    /// Required parameters; all must be understood or the request is rejected.
    pub required: Required,
    /// Optional parameters; unknown entries must be ignored by the host.
    pub optional: HashMap<String, Value>,
}

/// Latest request version this implementation produces and understands.
pub const SUPPORTED_REQUEST_VERSIONS: &[semver::Version] = &[Version::new(1, 0, 0)];

impl Request {
    /// Read a request from JSON-serialized bytes.
    pub fn from_reader(reader: impl Read) -> Result<Self, RequestError> {
        from_reader(reader).map_err(|source| RequestError::RequestDeserialization { source })
    }

    /// Write the request as JSON to a writer.
    pub fn to_writer(&self, writer: impl Write) -> Result<(), RequestError> {
        to_writer(writer, self).map_err(|source| RequestError::RequestSerialization { source })
    }

    /// Serialize the request to a JSON byte vector.
    pub fn to_json(&self) -> Result<Vec<u8>, RequestError> {
        let mut buf = Vec::new();
        self.to_writer(&mut buf)?;
        Ok(buf)
    }

    /// Parse a request from a JSON byte slice.
    pub fn from_json(bytes: &[u8]) -> Result<Self, RequestError> {
        Self::from_reader(bytes)
    }

    /// Validate that this host can understand the request.
    ///
    /// Per the protocol, every `required` parameter must be understood or the
    /// entire request is rejected; unknown `optional` entries are ignored.
    pub fn validate(&self) -> Result<(), RequestError> {
        if !SUPPORTED_REQUEST_VERSIONS.contains(&self.version) {
            return Err(RequestError::UnsupportedVersion {
                found: self.version.clone(),
                supported: SUPPORTED_REQUEST_VERSIONS.to_vec(),
            });
        }
        if self.required.input.hash_type != HashType::Sha2_0_11_Sha512_State {
            return Err(RequestError::InvalidContentType {
                actual: self.required.input.hash_type,
                expected: HashType::Sha2_0_11_Sha512_State,
            });
        }
        if !self.required.output.is_openpgp_v4() {
            return Err(RequestError::RequiredParameterNotUnderstood(format!(
                "signature type {:?}",
                self.required.output.sig_type
            )));
        }
        Ok(())
    }

    /// Prepare a signing request for a file.
    ///
    /// Hashes the file contents with SHA-512 and wraps the serialized hasher
    /// state into a version 1.0.0 request asking for an OpenPGP v4 signature.
    /// Unknown optional parameters (including a random "grease" entry, as in
    /// upstream) may be added by the host for forward compatibility.
    pub fn for_file(input: impl AsRef<Path>) -> Result<Self, RequestError> {
        let input = input.as_ref();
        let mut hasher = Sha512::new();
        {
            let mut file = File::open(input).map_err(|source| RequestError::IoPath {
                path: input.to_path_buf(),
                context: "opening the file for reading".to_string(),
                source,
            })?;
            let mut buf = [0u8; 8192];
            loop {
                let n = file
                    .read(&mut buf)
                    .map_err(|source| RequestError::IoPath {
                        path: input.to_path_buf(),
                        context: "reading the file contents".to_string(),
                        source,
                    })?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
        }
        let required = Required {
            input: SignatureRequestInput::from(hasher),
            output: SignatureRequestOutput::new_openpgp_v4(),
        };

        let grease: String = rand::rng()
            .sample_iter(&rand::distr::Alphanumeric)
            .take(7)
            .map(char::from)
            .collect();

        Ok(Self {
            version: Version::new(1, 0, 0),
            required,
            optional: [
                (
                    grease,
                    Value::String(
                        "https://gitlab.archlinux.org/archlinux/signstar/-/merge_requests/43"
                            .to_string(),
                    ),
                ),
                (
                    "request-time".into(),
                    Value::Number(
                        SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .map_err(|source| RequestError::CurrentTimeBeforeReference {
                                reference_time: SystemTime::UNIX_EPOCH,
                                source,
                            })?
                            .as_secs()
                            .into(),
                    ),
                ),
                (
                    "file-name".into(),
                    input
                        .file_name()
                        .and_then(|s| s.to_str())
                        .map(Into::into)
                        .unwrap_or(Value::Null),
                ),
            ]
            .into_iter()
            .collect(),
        })
    }
}

/// The response to a signing request.
///
/// Tracks the `version` of the signing response and the signature payload.
#[derive(Debug, Deserialize, Serialize)]
pub struct Response {
    /// Version of this signing response.
    pub version: Version,
    /// Raw content of the signature (base64 in the upstream protocol; the host
    /// writes the decoded bytes to the client).
    signature: String,
}

impl Response {
    /// Create a version 1 compatible response from raw signature content.
    pub fn v1(signature: String) -> Self {
        Self {
            version: Version::new(1, 0, 0),
            signature,
        }
    }

    /// Create a response from JSON-serialized bytes.
    pub fn from_reader(reader: impl Read) -> Result<Self, RequestError> {
        from_reader(reader).map_err(|source| RequestError::ResponseDeserialization { source })
    }

    /// Write the response as JSON to a writer.
    pub fn to_writer(&self, writer: impl Write) -> Result<(), RequestError> {
        to_writer(writer, self).map_err(|source| RequestError::ResponseSerialization { source })
    }

    /// Write the raw signature payload to a writer.
    pub fn signature_to_writer(&self, mut writer: impl Write) -> Result<(), RequestError> {
        writer
            .write_all(self.signature.as_bytes())
            .map_err(|source| RequestError::Io {
                context: "writing a signature to a buffer".to_string(),
                source,
            })
    }

    /// The signature payload as a string slice.
    pub fn signature(&self) -> &str {
        &self.signature
    }
}

/// The type of certificate generated for a signing key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum CertificateType {
    /// OpenPGP certificate.
    OpenPgp,
}

impl CertificateType {
    /// Present raw certificate bytes with correct protocol framing.
    ///
    /// For OpenPGP this produces an ASCII-armored public key block.
    pub fn with_framing(&self, raw_bytes: &[u8]) -> CertificateData {
        let encoded = BASE64.encode(raw_bytes);
        match self {
            CertificateType::OpenPgp => CertificateData(format!(
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n{encoded}\n-----END PGP PUBLIC KEY BLOCK-----"
            )),
        }
    }
}

/// Certificate data as presented to the user, with framing and base64 encoding.
#[derive(Debug, Deserialize, Serialize)]
pub struct CertificateData(String);

impl AsRef<str> for CertificateData {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Display for CertificateData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Data and metadata of a certificate stored in a Signstar backend.
#[derive(Debug, Deserialize, Serialize)]
pub struct Certificate {
    /// Base64-encoded certificate with protocol framing.
    pub certificate: CertificateData,
    /// The type of the certificate.
    pub r#type: CertificateType,
    /// The backend identifier, e.g. `NetHSM` or `YubiHSM2`.
    pub backend_id: BackendType,
    /// The signing key ID on that backend.
    pub signing_key_id: String,
}

/// List of certificates stored on the Signstar host.
#[derive(Debug, Deserialize, Serialize)]
pub struct Certificates {
    /// Array of framed, base64-encoded certificates.
    pub certs: Vec<Certificate>,
}
