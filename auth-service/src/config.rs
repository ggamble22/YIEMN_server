//! Configuration, loaded once at startup from environment variables
//! (12-factor style, so the same image runs in every environment).

use std::{net::SocketAddr, str::FromStr, time::Duration};

use anyhow::{Context, bail};
use axum::http::HeaderValue;

use crate::models::Role;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageBackend {
    DynamoDb,
    /// In-process store. For local hacking and tests only — never in production.
    Memory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhotoStorage {
    S3,
    /// In-process. Local development and tests only.
    Memory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhotoModeration {
    Rekognition,
    /// No screening. Local development and tests only — never in production.
    Off,
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
    /// Ids of the preset icons users may choose from (the frontend maps each id
    /// to artwork).
    pub user_icons: Vec<String>,

    // ---- photo icons ----
    pub photo_storage: PhotoStorage,
    pub photo_bucket: String,
    /// Override endpoint for S3-compatible stores (MinIO, LocalStack).
    pub s3_endpoint: Option<String>,
    /// Prefix for photo URLs returned to clients. Defaults to this service's own
    /// `/v1/photos`; point it at a CDN in front of that path in production.
    pub photo_public_base_url: String,
    /// Max upload size in bytes (before processing).
    pub photo_max_bytes: usize,
    pub photo_moderation: PhotoModeration,
    /// Rekognition confidence (0-100) at which a label rejects a photo.
    pub photo_moderation_min_confidence: f32,
    /// Roles allowed to upload a photo. Others can still use preset icons.
    pub photo_icon_roles: Vec<Role>,
    /// Cap on concurrent image decodes per pod (each can use up to ~100 MiB).
    pub max_concurrent_photo_jobs: usize,
}

/// Default icon set. Override with `USER_ICONS=a,b,c`. Removing an id later is
/// safe: users who had it keep it until they change it; clients fall back to a
/// default for ids they don't recognise.
pub const DEFAULT_USER_ICONS: &[&str] = &[
    "fox",
    "owl",
    "panda",
    "tiger",
    "penguin",
    "turtle",
    "dolphin",
    "koala",
    "rocket",
    "robot",
    "planet",
    "star",
    "book",
    "paintbrush",
    "soccer-ball",
    "music-note",
];

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

        let user_icons = match std::env::var("USER_ICONS") {
            Ok(raw) if !raw.trim().is_empty() => raw
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>(),
            _ => default_user_icons(),
        };
        if let Some(bad) = user_icons.iter().find(|id| !is_icon_id(id)) {
            bail!("USER_ICONS entry `{bad}` must be 1-32 chars of a-z, 0-9 or `-`");
        }

        let photo_storage = match env_or("PHOTO_STORAGE", "s3").to_lowercase().as_str() {
            "s3" => PhotoStorage::S3,
            "memory" => PhotoStorage::Memory,
            other => bail!("PHOTO_STORAGE must be `s3` or `memory`, got `{other}`"),
        };
        let photo_bucket = env_or("PHOTO_BUCKET", "");
        if photo_storage == PhotoStorage::S3 && photo_bucket.is_empty() {
            bail!("PHOTO_BUCKET must be set when PHOTO_STORAGE=s3");
        }
        let photo_moderation = match env_or("PHOTO_MODERATION", "rekognition")
            .to_lowercase()
            .as_str()
        {
            "rekognition" => PhotoModeration::Rekognition,
            "off" => PhotoModeration::Off,
            other => bail!("PHOTO_MODERATION must be `rekognition` or `off`, got `{other}`"),
        };
        let photo_icon_roles = env_or("PHOTO_ICON_ROLES", "student,parent,educator,admin")
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .map(|s| {
                Role::parse(&s).with_context(|| format!("unknown role `{s}` in PHOTO_ICON_ROLES"))
            })
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
            user_icons,
            photo_storage,
            photo_bucket,
            s3_endpoint: std::env::var("S3_ENDPOINT").ok().filter(|s| !s.is_empty()),
            photo_public_base_url: env_or("PHOTO_PUBLIC_BASE_URL", "/v1/photos")
                .trim_end_matches('/')
                .to_string(),
            photo_max_bytes: parse_env("PHOTO_MAX_BYTES", "5242880")?,
            photo_moderation,
            photo_moderation_min_confidence: parse_env("PHOTO_MODERATION_MIN_CONFIDENCE", "60")?,
            photo_icon_roles,
            max_concurrent_photo_jobs: parse_env("MAX_CONCURRENT_PHOTO_JOBS", "2")?,
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
            user_icons: default_user_icons(),
            photo_storage: PhotoStorage::Memory,
            photo_bucket: String::new(),
            s3_endpoint: None,
            photo_public_base_url: "/v1/photos".into(),
            photo_max_bytes: 5 * 1024 * 1024,
            photo_moderation: PhotoModeration::Off,
            photo_moderation_min_confidence: 60.0,
            photo_icon_roles: vec![Role::Student, Role::Parent, Role::Educator, Role::Admin],
            max_concurrent_photo_jobs: 2,
        }
    }
}

fn default_user_icons() -> Vec<String> {
    DEFAULT_USER_ICONS.iter().map(|s| s.to_string()).collect()
}

fn is_icon_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
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
