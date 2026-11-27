//! HTTPS (TLS) setup.
//!
//! Three modes, chosen by config:
//! - **Off**: plain HTTP. Right when something in front terminates TLS
//!   (the Kubernetes ingress, a cloud load balancer).
//! - **Files**: serve HTTPS with a PEM certificate chain + private key from
//!   disk (e.g. Let's Encrypt, or a Kubernetes TLS secret mounted as files).
//! - **Self-signed**: generate a throwaway certificate at startup. Local
//!   development only: browsers will warn, and every restart makes a new one.

use std::path::PathBuf;

use anyhow::Context;
use axum_server::tls_rustls::RustlsConfig;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsMode {
    Off,
    Files { cert: PathBuf, key: PathBuf },
    SelfSigned { hosts: Vec<String> },
}

impl TlsMode {
    pub fn is_enabled(&self) -> bool {
        !matches!(self, Self::Off)
    }
}

/// Build the rustls server config, or `None` for plain HTTP.
pub async fn server_config(mode: &TlsMode) -> anyhow::Result<Option<RustlsConfig>> {
    if !mode.is_enabled() {
        return Ok(None);
    }
    // Several crates in the tree pull in rustls; pick one crypto backend
    // explicitly so rustls never has to guess. Err = already installed: fine.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let config =
        match mode {
            TlsMode::Off => unreachable!(),
            TlsMode::Files { cert, key } => RustlsConfig::from_pem_file(cert, key)
                .await
                .with_context(|| {
                    format!(
                        "loading TLS certificate `{}` / key `{}`",
                        cert.display(),
                        key.display()
                    )
                })?,
            TlsMode::SelfSigned { hosts } => {
                let (cert_pem, key_pem) = self_signed_pem(hosts)?;
                RustlsConfig::from_pem(cert_pem.into_bytes(), key_pem.into_bytes())
                    .await
                    .context("loading generated self-signed certificate")?
            }
        };
    Ok(Some(config))
}

/// Generate a self-signed certificate valid for `hosts`. Returns `(cert, key)` as PEM.
pub fn self_signed_pem(hosts: &[String]) -> anyhow::Result<(String, String)> {
    let certified = rcgen::generate_simple_self_signed(hosts.to_vec())
        .context("generating self-signed certificate")?;
    Ok((certified.cert.pem(), certified.key_pair.serialize_pem()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_pem_pair() {
        let (cert, key) = self_signed_pem(&["localhost".into(), "127.0.0.1".into()]).unwrap();
        assert!(cert.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(key.contains("PRIVATE KEY-----"));
    }

    #[tokio::test]
    async fn off_means_plain_http() {
        assert!(server_config(&TlsMode::Off).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn self_signed_config_loads() {
        let mode = TlsMode::SelfSigned {
            hosts: vec!["localhost".into()],
        };
        assert!(server_config(&mode).await.unwrap().is_some());
    }
}
