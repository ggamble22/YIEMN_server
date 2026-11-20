//! In-memory `Repo` for tests and local experiments. Not for production:
//! state is per-process and lost on restart.

use std::{collections::HashMap, sync::Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::{ProfileUpdate, Repo, RepoError, RepoResult};
use crate::models::{Session, User};

#[derive(Default)]
pub struct MemoryRepo {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    users: HashMap<Uuid, User>,
    emails: HashMap<String, Uuid>,
    sessions: HashMap<(Uuid, Uuid), Session>,
}

impl MemoryRepo {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[async_trait]
impl Repo for MemoryRepo {
    async fn create_user(&self, user: &User) -> RepoResult<()> {
        let mut g = self.lock();
        if g.emails.contains_key(&user.email) {
            return Err(RepoError::EmailTaken);
        }
        g.emails.insert(user.email.clone(), user.id);
        g.users.insert(user.id, user.clone());
        Ok(())
    }

    async fn get_user(&self, id: Uuid) -> RepoResult<Option<User>> {
        Ok(self.lock().users.get(&id).cloned())
    }

    async fn get_user_by_email(&self, email: &str) -> RepoResult<Option<User>> {
        let g = self.lock();
        Ok(g.emails.get(email).and_then(|id| g.users.get(id)).cloned())
    }

    async fn update_profile(
        &self,
        id: Uuid,
        update: &ProfileUpdate,
        updated_at: DateTime<Utc>,
    ) -> RepoResult<Option<User>> {
        let mut g = self.lock();
        Ok(g.users.get_mut(&id).map(|u| {
            if let Some(name) = &update.display_name {
                u.display_name = name.clone();
            }
            if let Some(icon) = &update.icon {
                u.icon = icon.clone();
            }
            u.updated_at = updated_at;
            u.clone()
        }))
    }

    async fn create_session(&self, session: &Session) -> RepoResult<()> {
        self.lock()
            .sessions
            .insert((session.user_id, session.id), session.clone());
        Ok(())
    }

    async fn get_session(&self, user_id: Uuid, session_id: Uuid) -> RepoResult<Option<Session>> {
        Ok(self.lock().sessions.get(&(user_id, session_id)).cloned())
    }

    async fn rotate_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        old_hash: &str,
        new_hash: &str,
        new_expires_at: DateTime<Utc>,
    ) -> RepoResult<bool> {
        let mut g = self.lock();
        match g.sessions.get_mut(&(user_id, session_id)) {
            Some(s) if s.token_hash == old_hash => {
                s.token_hash = new_hash.to_string();
                s.expires_at = new_expires_at;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn delete_session(&self, user_id: Uuid, session_id: Uuid) -> RepoResult<()> {
        self.lock().sessions.remove(&(user_id, session_id));
        Ok(())
    }

    async fn delete_all_sessions(&self, user_id: Uuid) -> RepoResult<()> {
        self.lock().sessions.retain(|(uid, _), _| *uid != user_id);
        Ok(())
    }

    async fn ping(&self) -> RepoResult<()> {
        Ok(())
    }
}
