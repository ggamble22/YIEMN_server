//! Persistence boundary. Handlers depend only on the `Repo` trait, so the
//! storage engine can be swapped (or faked in tests) without touching them.

pub mod dynamo;
pub mod memory;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::models::{Icon, Session, User};

#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error("email already registered")]
    EmailTaken,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type RepoResult<T> = Result<T, RepoError>;

/// A partial profile update. `None` fields are left unchanged.
#[derive(Clone, Debug, Default)]
pub struct ProfileUpdate {
    pub display_name: Option<String>,
    /// `Some(Some(icon))` sets the icon, `Some(None)` clears it.
    pub icon: Option<Option<Icon>>,
}

impl ProfileUpdate {
    pub fn is_empty(&self) -> bool {
        self.display_name.is_none() && self.icon.is_none()
    }
}

#[async_trait]
pub trait Repo: Send + Sync + 'static {
    /// Atomically create the user and reserve the email. `EmailTaken` on conflict.
    async fn create_user(&self, user: &User) -> RepoResult<()>;
    async fn get_user(&self, id: Uuid) -> RepoResult<Option<User>>;
    async fn get_user_by_email(&self, email: &str) -> RepoResult<Option<User>>;
    /// Apply a partial update. Returns the updated user, or `None` if it doesn't exist.
    async fn update_profile(
        &self,
        id: Uuid,
        update: &ProfileUpdate,
        updated_at: DateTime<Utc>,
    ) -> RepoResult<Option<User>>;

    async fn create_session(&self, session: &Session) -> RepoResult<()>;
    async fn get_session(&self, user_id: Uuid, session_id: Uuid) -> RepoResult<Option<Session>>;
    /// Compare-and-swap the token hash. Returns `false` if `old_hash` no longer
    /// matches (concurrent rotation / replay) or the session is gone.
    async fn rotate_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        old_hash: &str,
        new_hash: &str,
        new_expires_at: DateTime<Utc>,
    ) -> RepoResult<bool>;
    async fn delete_session(&self, user_id: Uuid, session_id: Uuid) -> RepoResult<()>;
    async fn delete_all_sessions(&self, user_id: Uuid) -> RepoResult<()>;

    /// Cheap connectivity check for readiness probes.
    async fn ping(&self) -> RepoResult<()>;
}
