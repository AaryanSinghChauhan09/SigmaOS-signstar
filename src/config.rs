//! Signstar configuration file locations and precedence.
//!
//! Ported from `archlinux/signstar` `signstar-common::config`. Configuration
//! files named `config.toml` are resolved with the following precedence
//! (highest first):
//!
//! - `/etc/signstar`
//! - `/run/signstar`
//! - `/usr/local/share/signstar`
//! - `/usr/share/signstar`

use std::{fs::create_dir_all, path::PathBuf};

/// An error that may occur when handling configuration directories or files.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A directory can not be created.
    #[error("unable to create directory {dir}: {source}")]
    CreateDirectory {
        /// The directory that cannot be created.
        dir: String,
        /// The source error.
        #[source]
        source: std::io::Error,
    },
}

/// The default config directory below "/usr" for Signstar hosts.
pub const DEFAULT_CONFIG_DIR: &str = "/usr/share/signstar/";
/// The override config directory below "/etc" for Signstar hosts.
pub const ETC_OVERRIDE_CONFIG_DIR: &str = "/etc/signstar/";
/// The override config directory below "/run" for Signstar hosts.
pub const RUN_OVERRIDE_CONFIG_DIR: &str = "/run/signstar/";
/// The override config directory below "/usr/local" for Signstar hosts.
pub const USR_LOCAL_OVERRIDE_CONFIG_DIR: &str = "/usr/local/share/signstar/";
/// The filename of a Signstar configuration file.
pub const CONFIG_FILE: &str = "config.toml";

/// Ordered list of config directories, highest precedence first.
pub const CONFIG_DIRS_BY_PRECEDENCE: [&str; 4] = [
    ETC_OVERRIDE_CONFIG_DIR,
    RUN_OVERRIDE_CONFIG_DIR,
    USR_LOCAL_OVERRIDE_CONFIG_DIR,
    DEFAULT_CONFIG_DIR,
];

/// Returns the first Signstar configuration file available, or `None`.
pub fn get_config_file() -> Option<PathBuf> {
    get_config_file_paths()
        .into_iter()
        .find(|file| file.is_file())
}

/// Returns the first Signstar configuration file, or the default path.
pub fn get_config_file_or_default() -> PathBuf {
    get_config_file().unwrap_or_else(get_default_config_file_path)
}

/// All configuration file paths, sorted by descending precedence.
pub fn get_config_file_paths() -> Vec<PathBuf> {
    CONFIG_DIRS_BY_PRECEDENCE
        .iter()
        .map(|dir| PathBuf::from([*dir, CONFIG_FILE].concat()))
        .collect()
}

/// Config file path for the /etc override directory.
pub fn get_etc_override_config_file_path() -> PathBuf {
    PathBuf::from([ETC_OVERRIDE_CONFIG_DIR, CONFIG_FILE].concat())
}

/// Config directory path for the /etc override directory.
pub fn get_etc_override_dir_path() -> PathBuf {
    PathBuf::from(ETC_OVERRIDE_CONFIG_DIR)
}

/// Config file path for the /run override directory.
pub fn get_run_override_config_file_path() -> PathBuf {
    PathBuf::from([RUN_OVERRIDE_CONFIG_DIR, CONFIG_FILE].concat())
}

/// Config directory path for the /run override directory.
pub fn get_run_override_dir_path() -> PathBuf {
    PathBuf::from(RUN_OVERRIDE_CONFIG_DIR)
}

/// Config file path for the /usr/local override directory.
pub fn get_usr_local_override_config_file_path() -> PathBuf {
    PathBuf::from([USR_LOCAL_OVERRIDE_CONFIG_DIR, CONFIG_FILE].concat())
}

/// Config directory path for the /usr/local override directory.
pub fn get_usr_local_override_dir_path() -> PathBuf {
    PathBuf::from(USR_LOCAL_OVERRIDE_CONFIG_DIR)
}

/// Default config file path below /usr.
pub fn get_default_config_file_path() -> PathBuf {
    PathBuf::from([DEFAULT_CONFIG_DIR, CONFIG_FILE].concat())
}

/// Default config directory path below /usr.
pub fn get_default_config_dir_path() -> PathBuf {
    PathBuf::from(DEFAULT_CONFIG_DIR)
}

/// Create the default config directory below /usr.
pub fn create_default_config_dir() -> Result<(), ConfigError> {
    create_dir_all(get_default_config_dir_path()).map_err(|source| ConfigError::CreateDirectory {
        dir: DEFAULT_CONFIG_DIR.to_string(),
        source,
    })
}

/// Create the /etc override config directory.
pub fn create_etc_override_config_dir() -> Result<(), ConfigError> {
    create_dir_all(get_etc_override_dir_path()).map_err(|source| ConfigError::CreateDirectory {
        dir: ETC_OVERRIDE_CONFIG_DIR.to_string(),
        source,
    })
}

/// Create the /run override config directory.
pub fn create_run_override_config_dir() -> Result<(), ConfigError> {
    create_dir_all(get_run_override_dir_path()).map_err(|source| ConfigError::CreateDirectory {
        dir: RUN_OVERRIDE_CONFIG_DIR.to_string(),
        source,
    })
}

/// Create the /usr/local override config directory.
pub fn create_usr_local_override_config_dir() -> Result<(), ConfigError> {
    create_dir_all(get_usr_local_override_dir_path()).map_err(|source| {
        ConfigError::CreateDirectory {
            dir: USR_LOCAL_OVERRIDE_CONFIG_DIR.to_string(),
            source,
        }
    })
}

/// A testable resolver for Signstar configuration files under an arbitrary
/// root directory.
///
/// Mirrors the production precedence but lets callers (and tests) point at a
/// scratch hierarchy instead of the real `/etc`, `/run`, `/usr` tree.
#[derive(Debug, Clone)]
pub struct ConfigResolver {
    dirs_by_precedence: Vec<PathBuf>,
}

impl ConfigResolver {
    /// Build a resolver over the four standard directories below `root`,
    /// preserving production precedence order.
    pub fn new(root: impl AsRef<std::path::Path>) -> Self {
        let root = root.as_ref();
        Self {
            dirs_by_precedence: [
                "etc/signstar",
                "run/signstar",
                "usr/local/share/signstar",
                "usr/share/signstar",
            ]
            .iter()
            .map(|rel| root.join(rel))
            .collect(),
        }
    }

    /// All candidate `config.toml` paths, highest precedence first.
    pub fn config_file_paths(&self) -> Vec<PathBuf> {
        self.dirs_by_precedence
            .iter()
            .map(|dir| dir.join(CONFIG_FILE))
            .collect()
    }

    /// The first existing `config.toml`, or `None` if none exists.
    pub fn config_file(&self) -> Option<PathBuf> {
        self.config_file_paths()
            .into_iter()
            .find(|file| file.is_file())
    }

    /// The first existing `config.toml`, or the lowest-precedence default.
    pub fn config_file_or_default(&self) -> PathBuf {
        self.config_file()
            .unwrap_or_else(|| self.dirs_by_precedence[3].join(CONFIG_FILE))
    }

    /// The directory paths, highest precedence first.
    pub fn dirs(&self) -> &[PathBuf] {
        &self.dirs_by_precedence
    }
}
