//! Domain types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Student,
    Parent,
    Educator,
    /// Never self-assignable via signup.
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Student => "student",
            Self::Parent => "parent",
            Self::Educator => "educator",
            Self::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "student" => Some(Self::Student),
            "parent" => Some(Self::Parent),
            "educator" => Some(Self::Educator),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
}

/// A user's chosen icon.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Icon {
    /// An id from the configured preset set (`Config::user_icons`).
    Preset(String),
    /// An uploaded photo, stored under this object key (see `crate::media`).
    Photo { key: String },
}

impl Icon {
    pub fn photo_key(&self) -> Option<&str> {
        match self {
            Self::Photo { key } => Some(key),
            Self::Preset(_) => None,
        }
    }
}

/// How an icon is shown to clients.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum PublicIcon {
    Preset { id: String },
    Photo { url: String },
}

/// Full user record, including the password hash. Never serialise this to clients.
#[derive(Clone, Debug)]
pub struct User {
    pub id: Uuid,
    /// Normalised (trimmed, lower-cased).
    pub email: String,
    pub display_name: String,
    /// Optional avatar: a preset icon or an uploaded photo.
    pub icon: Option<Icon>,
    pub role: Role,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// What clients see.
#[derive(Clone, Debug, Serialize)]
pub struct PublicUser {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    /// `null` when the user hasn't picked one; clients show a default.
    /// Otherwise `{"type":"preset","id":"fox"}` or `{"type":"photo","url":"..."}`.
    pub icon: Option<PublicIcon>,
    pub role: Role,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl PublicUser {
    /// `photo_base_url` is `Config::photo_public_base_url`.
    pub fn new(u: &User, photo_base_url: &str) -> Self {
        Self {
            id: u.id,
            email: u.email.clone(),
            display_name: u.display_name.clone(),
            icon: u.icon.as_ref().map(|icon| match icon {
                Icon::Preset(id) => PublicIcon::Preset { id: id.clone() },
                Icon::Photo { key } => PublicIcon::Photo {
                    url: format!("{photo_base_url}/{key}"),
                },
            }),
            role: u.role,
            created_at: u.created_at,
            updated_at: u.updated_at,
        }
    }
}

/// A refresh-token session (one per signed-in device).
#[derive(Clone, Debug)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    /// SHA-256 (hex) of the refresh token secret. The secret itself is never stored.
    pub token_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub user_agent: Option<String>,
}
