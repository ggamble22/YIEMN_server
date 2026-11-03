//! Opaque refresh tokens: `<user_id>.<session_id>.<secret>`.
//!
//! The ids let us find the session with a single key lookup; only a SHA-256 of
//! the 256-bit random secret is stored, so a database leak can't mint sessions.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

pub struct ParsedRefreshToken {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub secret: String,
}

/// Returns `(token_for_client, hash_to_store)`.
pub fn generate(user_id: Uuid, session_id: Uuid) -> (String, String) {
    let secret = new_secret();
    let hash = hash_secret(&secret);
    (encode(user_id, session_id, &secret), hash)
}

/// Returns `(secret, hash)` for rotating an existing session.
pub fn new_secret_and_hash() -> (String, String) {
    let secret = new_secret();
    let hash = hash_secret(&secret);
    (secret, hash)
}

pub fn encode(user_id: Uuid, session_id: Uuid, secret: &str) -> String {
    format!("{user_id}.{session_id}.{secret}")
}

pub fn parse(token: &str) -> Option<ParsedRefreshToken> {
    if token.len() > 256 {
        return None;
    }
    let mut parts = token.split('.');
    let user_id = Uuid::parse_str(parts.next()?).ok()?;
    let session_id = Uuid::parse_str(parts.next()?).ok()?;
    let secret = parts.next()?.to_string();
    if parts.next().is_some() || secret.is_empty() {
        return None;
    }
    Some(ParsedRefreshToken {
        user_id,
        session_id,
        secret,
    })
}

pub fn hash_secret(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

/// Constant-time comparison of two hex hashes.
pub fn hashes_match(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

fn new_secret() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_parse_roundtrip() {
        let (u, s) = (Uuid::now_v7(), Uuid::new_v4());
        let (token, hash) = generate(u, s);
        let p = parse(&token).expect("parses");
        assert_eq!((p.user_id, p.session_id), (u, s));
        assert!(hashes_match(&hash_secret(&p.secret), &hash));
    }

    #[test]
    fn rejects_malformed() {
        let empty_secret = format!("{}.{}.", Uuid::nil(), Uuid::nil());
        let extra_part = format!("{}.{}.s.extra", Uuid::nil(), Uuid::nil());
        for bad in ["", "a.b.c", "x", empty_secret.as_str(), extra_part.as_str()] {
            assert!(parse(bad).is_none(), "{bad}");
        }
    }
}
