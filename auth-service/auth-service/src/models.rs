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

/// Full user record, including the password hash. Never serialise this to clients.
#[derive(Clone, Debug)]
pub struct User {
    pub id: Uuid,
    /// Normalised (trimmed, lower-cased).
    pub email: String,
    pub display_name: String,
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
    pub role: Role,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&User> for PublicUser {
    fn from(u: &User) -> Self {
        Self {
            id: u.id,
            email: u.email.clone(),
            display_name: u.display_name.clone(),
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
