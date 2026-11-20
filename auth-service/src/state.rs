//! Shared, cheaply-clonable application state.

use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::{
    auth::{jwt::JwtKeys, password::PasswordService},
    config::Config,
    media::{Moderator, PhotoStore},
    middleware::rate_limit::RateLimiter,
    repo::Repo,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub repo: Arc<dyn Repo>,
    pub jwt: Arc<JwtKeys>,
    pub passwords: Arc<PasswordService>,
    pub limiter: Arc<RateLimiter>,
    pub photos: Arc<dyn PhotoStore>,
    pub moderator: Arc<dyn Moderator>,
    /// Bounds concurrent image decodes (CPU + memory heavy).
    pub photo_jobs: Arc<Semaphore>,
}

impl AppState {
    pub fn new(
        config: Config,
        repo: Arc<dyn Repo>,
        photos: Arc<dyn PhotoStore>,
        moderator: Arc<dyn Moderator>,
    ) -> anyhow::Result<Self> {
        let jwt = JwtKeys::new(
            &config.jwt_secret,
            &config.jwt_issuer,
            config.access_token_ttl_secs,
        );
        let passwords = PasswordService::new(config.max_concurrent_hashes)?;
        let limiter = RateLimiter::per_minute(config.rate_limit_per_minute);
        let photo_jobs = Semaphore::new(config.max_concurrent_photo_jobs.max(1));
        Ok(Self {
            config: Arc::new(config),
            repo,
            jwt: Arc::new(jwt),
            passwords: Arc::new(passwords),
            limiter: Arc::new(limiter),
            photos,
            moderator,
            photo_jobs: Arc::new(photo_jobs),
        })
    }
}
