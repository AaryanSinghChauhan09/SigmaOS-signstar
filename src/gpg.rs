//! GPG-backed signing backend.
//!
//! Implements [`Signer`] by shelling out to `gpg --detach-sign` — the
//! production path for a signstar host on a normal machine (HSMs remain
//! possible via other backends).

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::backend::{BackendType, Signer};
use crate::error::HostError;
use crate::request::Request;

/// A signer that produces real OpenPGP detached signatures via `gpg`.
#[derive(Debug, Clone)]
pub struct GpgSigner {
    /// Path to gpg binary.
    pub gpg: PathBuf,
    /// Key id/fingerprint to sign with (`-u`).
    pub key_id: String,
    /// Extra args (e.g. `--pinentry-mode loopback`).
    pub extra_args: Vec<String>,
    /// Reported backend type.
    pub backend: BackendType,
}

impl GpgSigner {
    /// New signer for `key_id` using `gpg` on PATH.
    pub fn new(key_id: impl Into<String>) -> Self {
        Self {
            gpg: PathBuf::from("gpg"),
            key_id: key_id.into(),
            extra_args: Vec::new(),
            backend: BackendType::NetHSM,
        }
    }

    /// With an explicit gpg binary path.
    pub fn with_gpg(mut self, path: impl Into<PathBuf>) -> Self {
        self.gpg = path.into();
        self
    }
}

impl Signer for GpgSigner {
    fn sign(&self, digest: &[u8; 32], _request: &Request) -> Result<Vec<u8>, HostError> {
        let mut cmd = Command::new(&self.gpg);
        cmd.arg("--batch")
            .arg("--yes")
            .arg("--detach-sign")
            .arg("--armor")
            .arg("-u")
            .arg(&self.key_id)
            .args(&self.extra_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| {
            HostError::Backend(format!("spawning {}: {e}", self.gpg.display()))
        })?;
        {
            let mut stdin = child.stdin.take().ok_or_else(|| {
                HostError::Backend("gpg stdin unavailable".into())
            })?;
            stdin
                .write_all(digest)
                .map_err(|e| HostError::Backend(format!("writing to gpg: {e}")))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| HostError::Backend(format!("waiting on gpg: {e}")))?;
        if !out.status.success() {
            return Err(HostError::Backend(format!(
                "gpg failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(out.stdout)
    }

    fn backend_type(&self) -> BackendType {
        self.backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpg_signer_config() {
        let s = GpgSigner::new("A1B2C3").with_gpg("/usr/bin/gpg2");
        assert_eq!(s.gpg, PathBuf::from("/usr/bin/gpg2"));
        assert_eq!(s.key_id, "A1B2C3");
    }

    #[test]
    fn test_gpg_signer_missing_binary_errors() {
        // Point at a nonexistent binary; sign must error, not panic.
        let s = GpgSigner::new("x").with_gpg("/nonexistent/gpg");
        let path = std::env::temp_dir().join("signstar-test-payload");
        std::fs::write(&path, b"payload").unwrap();
        let req = crate::request::Request::for_file(&path).unwrap();
        let digest = [0u8; 32];
        assert!(s.sign(&digest, &req).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
