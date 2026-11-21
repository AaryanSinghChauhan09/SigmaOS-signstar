//! SigmaOS signstar component.
//!
//! Rust implementation of the [Signstar](https://signstar.archlinux.page)
//! secure-enclave signing protocol, modelled on
//! [`archlinux/signstar`](https://github.com/archlinux/signstar)
//! (`signstar-common`, `signstar-config`, `signstar-host`).
//!
//! Provides the JSON signing request/response protocol, configuration file
//! resolution, certificate framing, and a host that validates requests and
//! delegates signing to a pluggable [`backend::Signer`] backend (HSM in
//! production, [`backend::LocalFileSigner`] for development).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod backend;
pub mod config;
pub mod error;
pub mod request;

pub use backend::{BackendType, Host, LocalFileSigner, Signer};
pub use config::{
    CONFIG_DIRS_BY_PRECEDENCE, CONFIG_FILE, ConfigError, ConfigResolver, DEFAULT_CONFIG_DIR,
    ETC_OVERRIDE_CONFIG_DIR, RUN_OVERRIDE_CONFIG_DIR, USR_LOCAL_OVERRIDE_CONFIG_DIR,
    create_default_config_dir, create_etc_override_config_dir, create_run_override_config_dir,
    create_usr_local_override_config_dir, get_config_file, get_config_file_or_default,
    get_config_file_paths, get_default_config_dir_path, get_default_config_file_path,
    get_etc_override_config_file_path, get_etc_override_dir_path, get_run_override_config_file_path,
    get_run_override_dir_path, get_usr_local_override_config_file_path,
    get_usr_local_override_dir_path,
};
pub use error::{HostError, RequestError};
pub use request::{
    Certificate, CertificateData, CertificateType, Certificates, HashType, Request,
    Required, Response, SUPPORTED_REQUEST_VERSIONS, SignatureRequestInput,
    SignatureRequestOutput, SignatureType,
};
