//! Configuration, loaded once at startup from environment variables
//! (12-factor style, so the same image runs in every environment).

use std::{net::SocketAddr, str::FromStr, time::Duration};

use anyhow::{Context, bail};
use axum::http::HeaderValue;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageBackend {
    DynamoDb,
    /// In-process store. For local hacking and tests only — never in production.
    Memory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

/// Service configuration. Deliberately not `Debug`: it holds the JWT secret.
#[derive(Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub metrics_addr: SocketAddr,
    pub storage: StorageBackend,
    pub dynamodb_table: String,
    /// Override endpoint, e.g. `http://localhost:8000` for DynamoDB Local.
    pub dynamodb_endpoint: Option<String>,
    pub jwt_secret: String,
    pub jwt_issuer: String,
    pub access_token_ttl_secs: i64,
    pub refresh_token_ttl_secs: i64,
    /// Requests per minute per client IP on signup/login/refresh. 0 disables.
    pub rate_limit_per_minute: u32,
    /// Use the right-most `X-Forwarded-For` hop as the client IP. Only enable
    /// behind exactly one trusted proxy / load balancer that appends to it.
    pub trust_forwarded_for: bool,
    pub cors_allowed_origins: Vec<HeaderValue>,
    pub request_timeout: Duration,
    /// Cap on concurrent Argon2 operations per pod (each uses ~19 MiB RAM).
    pub max_concurrent_hashes: usize,
    pub log_format: LogFormat,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let storage = match env_or("STORAGE_BACKEND", "dynamodb")
            .to_lowercase()
            .as_str()
        {
            "dynamodb" => StorageBackend::DynamoDb,
            "memory" => StorageBackend::Memory,
            other => bail!("STORAGE_BACKEND must be `dynamodb` or `memory`, got `{other}`"),
        };

        let jwt_secret = std::env::var("JWT_SECRET").context("JWT_SECRET must be set")?;
        if jwt_secret.len() < 32 {
            bail!("JWT_SECRET must be at least 32 bytes");
        }

        let log_format = match env_or("LOG_FORMAT", "json").to_lowercase().as_str() {
            "pretty" => LogFormat::Pretty,
            _ => LogFormat::Json,
        };

        let cors_allowed_origins = env_or("CORS_ALLOWED_ORIGINS", "")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| HeaderValue::from_str(s).with_context(|| format!("invalid CORS origin `{s}`")))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let default_hashes = std::thread::available_parallelism()
            .map(|n| n.get() * 2)
            .unwrap_or(4);

        Ok(Self {
            bind_addr: parse_env("BIND_ADDR", "0.0.0.0:8080")?,
            metrics_addr: parse_env("METRICS_ADDR", "0.0.0.0:9090")?,
            storage,
            dynamodb_table: env_or("DYNAMODB_TABLE", "auth"),
            dynamodb_endpoint: std::env::var("DYNAMODB_ENDPOINT")
                .ok()
                .filter(|s| !s.is_empty()),
            jwt_secret,
            jwt_issuer: env_or("JWT_ISSUER", "auth-service"),
            access_token_ttl_secs: parse_env("ACCESS_TOKEN_TTL_SECS", "900")?,
            refresh_token_ttl_secs: parse_env("REFRESH_TOKEN_TTL_SECS", "2592000")?,
            rate_limit_per_minute: parse_env("RATE_LIMIT_PER_MINUTE", "30")?,
            trust_forwarded_for: parse_env("TRUST_FORWARDED_FOR", "false")?,
            cors_allowed_origins,
            request_timeout: Duration::from_secs(parse_env("REQUEST_TIMEOUT_SECS", "10")?),
            max_concurrent_hashes: parse_env("MAX_CONCURRENT_HASHES", &default_hashes.to_string())?,
            log_format,
        })
    }

    /// Defaults suitable for in-process tests.
    pub fn test_default() -> Self {
        Self {
            bind_addr: "127.0.0.1:0".parse().expect("valid addr"),
            metrics_addr: "127.0.0.1:0".parse().expect("valid addr"),
            storage: StorageBackend::Memory,
            dynamodb_table: "auth-test".into(),
            dynamodb_endpoint: None,
            jwt_secret: "test-secret-that-is-at-least-32-bytes-long".into(),
            jwt_issuer: "auth-service-test".into(),
            access_token_ttl_secs: 900,
            refresh_token_ttl_secs: 3600,
            rate_limit_per_minute: 0,
            trust_forwarded_for: false,
            cors_allowed_origins: Vec::new(),
            request_timeout: Duration::from_secs(10),
            max_concurrent_hashes: 4,
            log_format: LogFormat::Pretty,
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn parse_env<T>(key: &str, default: &str) -> anyhow::Result<T>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    let raw = env_or(key, default);
    raw.parse::<T>()
        .map_err(|e| anyhow::anyhow!("invalid value for {key} (`{raw}`): {e}"))
}
