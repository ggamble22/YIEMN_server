//! Argon2id password hashing.
//!
//! Hashing is deliberately expensive (CPU + ~19 MiB RAM each), so it runs on
//! the blocking thread pool and is capped by a semaphore. That keeps the async
//! runtime responsive and pod memory bounded under login storms.

use anyhow::anyhow;
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use tokio::sync::Semaphore;

use crate::error::ApiError;

pub struct PasswordService {
    permits: Semaphore,
    /// Verified against when the email doesn't exist, so "unknown user" and
    /// "wrong password" take the same time (no account enumeration by timing).
    dummy_hash: String,
}

impl PasswordService {
    pub fn new(max_concurrent: usize) -> anyhow::Result<Self> {
        Ok(Self {
            permits: Semaphore::new(max_concurrent.max(1)),
            dummy_hash: hash_blocking("timing-equaliser-not-a-real-password")?,
        })
    }

    pub async fn hash(&self, password: String) -> Result<String, ApiError> {
        let _permit = self
            .permits
            .acquire()
            .await
            .map_err(|_| ApiError::Unavailable)?;
        let hash = tokio::task::spawn_blocking(move || hash_blocking(&password))
            .await
            .map_err(anyhow::Error::from)??;
        Ok(hash)
    }

    /// Returns true only if `stored_hash` is `Some` and matches.
    pub async fn verify(
        &self,
        password: String,
        stored_hash: Option<String>,
    ) -> Result<bool, ApiError> {
        let (hash, is_real) = match stored_hash {
            Some(h) => (h, true),
            None => (self.dummy_hash.clone(), false),
        };
        let _permit = self
            .permits
            .acquire()
            .await
            .map_err(|_| ApiError::Unavailable)?;
        let matches = tokio::task::spawn_blocking(move || verify_blocking(&password, &hash))
            .await
            .map_err(anyhow::Error::from)?;
        Ok(matches && is_real)
    }
}

fn hash_blocking(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow!("argon2 hash failed: {e}"))
}

fn verify_blocking(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hash_and_verify() {
        let svc = PasswordService::new(2).unwrap();
        let h = svc.hash("correct horse".into()).await.unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(
            svc.verify("correct horse".into(), Some(h.clone()))
                .await
                .unwrap()
        );
        assert!(!svc.verify("wrong".into(), Some(h)).await.unwrap());
        assert!(!svc.verify("anything".into(), None).await.unwrap());
    }
}
