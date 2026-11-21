//! Error types for the Signstar signing protocol and host configuration.

use std::path::PathBuf;

use crate::request::{HashType, SignatureType};

/// Errors that can occur while handling signing requests and responses.
#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    /// The JSON request could not be deserialized.
    #[error("could not deserialize request: {source}")]
    RequestDeserialization {
        /// The underlying error.
        #[source]
        source: serde_json::Error,
    },

    /// The JSON request could not be serialized.
    #[error("could not serialize request: {source}")]
    RequestSerialization {
        /// The underlying error.
        #[source]
        source: serde_json::Error,
    },

    /// The JSON response could not be deserialized.
    #[error("could not deserialize response: {source}")]
    ResponseDeserialization {
        /// The underlying error.
        #[source]
        source: serde_json::Error,
    },

    /// The JSON response could not be serialized.
    #[error("could not serialize response: {source}")]
    ResponseSerialization {
        /// The underlying error.
        #[source]
        source: serde_json::Error,
    },

    /// An I/O error occurred at a path.
    #[error("I/O error at path {path} while {context}: {source}")]
    IoPath {
        /// The path involved.
        path: PathBuf,
        /// What was being done.
        context: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// An I/O error occurred without a specific path.
    #[error("I/O error while {context}: {source}")]
    Io {
        /// What was being done.
        context: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The system clock is before the Unix epoch.
    #[error("current time is before reference time {reference_time:?}: {source}")]
    CurrentTimeBeforeReference {
        /// The reference time.
        reference_time: std::time::SystemTime,
        /// The underlying error.
        #[source]
        source: std::time::SystemTimeError,
    },

    /// The hasher state could not be deserialized.
    #[error("deserialization of the hasher state failed: {0}")]
    HasherDeserialization(#[source] sha2::digest::common::hazmat::DeserializeStateError),

    /// The hasher state content is misaligned.
    #[error("content size ({size} bytes) is misaligned: {source}")]
    HasherMisalignedSize {
        /// Size of the provided content in bytes.
        size: usize,
        /// The underlying error.
        #[source]
        source: std::array::TryFromSliceError,
    },

    /// The request input hash type is not the expected one.
    #[error("invalid content type: found {actual:?} but expected {expected:?}")]
    InvalidContentType {
        /// The hash type that was found.
        actual: HashType,
        /// The hash type that was expected.
        expected: HashType,
    },

    /// The request version is not supported by this implementation.
    #[error("unsupported request version {found}; supported versions: {supported:?}")]
    UnsupportedVersion {
        /// The version found in the request.
        found: semver::Version,
        /// Versions this implementation understands.
        supported: Vec<semver::Version>,
    },

    /// A required request parameter is missing or not understood.
    #[error("required parameter not understood: {0}")]
    RequiredParameterNotUnderstood(String),
}

/// Errors that can occur on the signing host while processing a request.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    /// The request could not be parsed.
    #[error("invalid signing request: {0}")]
    InvalidRequest(#[from] RequestError),

    /// The request requires a hash type this host does not support.
    #[error("unsupported input hash type: {0:?}")]
    UnsupportedHashType(HashType),

    /// The request asks for a signature type this host does not produce.
    #[error("unsupported signature type: {0:?}")]
    UnsupportedSignatureType(SignatureType),

    /// The backend failed to produce a signature.
    #[error("signing backend error: {0}")]
    Backend(String),
}
