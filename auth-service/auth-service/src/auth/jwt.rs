//! Short-lived JWT access tokens.
//!
//! Other services verify these locally with the shared key — they never call
//! this service per request, which is what lets the ecosystem scale.

use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::{Role, User};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claims {
    /// User id.
    pub sub: Uuid,
    pub role: Role,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
    /// Unique token id (useful for audit logs / future deny-lists).
    pub jti: Uuid,
}

pub struct JwtKeys {
    encoding: EncodingKey,
    decoding: DecodingKey,
    validation: Validation,
    issuer: String,
    ttl_secs: i64,
}

impl JwtKeys {
    pub fn new(secret: &str, issuer: &str, ttl_secs: i64) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[issuer]);
        validation.leeway = 30;
        Self {
            encoding: EncodingKey::from_secret(secret.as_bytes()),
            decoding: DecodingKey::from_secret(secret.as_bytes()),
            validation,
            issuer: issuer.to_string(),
            ttl_secs,
        }
    }

    /// Returns `(token, expires_in_secs)`.
    pub fn issue(&self, user: &User) -> anyhow::Result<(String, i64)> {
        let now = Utc::now().timestamp();
        let claims = Claims {
            sub: user.id,
            role: user.role,
            iss: self.issuer.clone(),
            iat: now,
            exp: now + self.ttl_secs,
            jti: Uuid::new_v4(),
        };
        let token = encode(&Header::new(Algorithm::HS256), &claims, &self.encoding)?;
        Ok((token, self.ttl_secs))
    }

    pub fn verify(&self, token: &str) -> anyhow::Result<Claims> {
        Ok(decode::<Claims>(token, &self.decoding, &self.validation)?.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user() -> User {
        let now = Utc::now();
        User {
            id: Uuid::now_v7(),
            email: "a@b.co".into(),
            display_name: "A".into(),
            role: Role::Student,
            password_hash: String::new(),
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn roundtrip_and_rejects_foreign_tokens() {
        let keys = JwtKeys::new("k".repeat(32).as_str(), "iss", 60);
        let u = user();
        let (t, _) = keys.issue(&u).unwrap();
        assert_eq!(keys.verify(&t).unwrap().sub, u.id);

        let other_key = JwtKeys::new("z".repeat(32).as_str(), "iss", 60);
        assert!(other_key.verify(&t).is_err());
        let other_iss = JwtKeys::new("k".repeat(32).as_str(), "other", 60);
        assert!(other_iss.verify(&t).is_err());
    }

    #[test]
    fn rejects_expired() {
        let keys = JwtKeys::new("k".repeat(32).as_str(), "iss", -120);
        let (t, _) = keys.issue(&user()).unwrap();
        assert!(keys.verify(&t).is_err());
    }
}
