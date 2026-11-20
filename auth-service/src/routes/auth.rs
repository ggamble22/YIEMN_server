//! Signup, login, token refresh and logout.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::{AuthUser, refresh as tokens},
    error::ApiError,
    models::{Icon, PublicUser, Role, Session, User},
    routes::json::ApiJson,
    state::AppState,
    validate,
};

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    pub display_name: String,
    /// Defaults to `student`. `admin` is rejected.
    #[serde(default)]
    pub role: Option<Role>,
    /// Optional icon id from `GET /v1/users/icons`.
    #[serde(default)]
    pub icon: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    /// Access-token lifetime in seconds.
    pub expires_in: i64,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub user: PublicUser,
    #[serde(flatten)]
    pub tokens: TokenPair,
}

/// POST /v1/auth/signup
pub async fn signup(
    State(st): State<AppState>,
    headers: HeaderMap,
    ApiJson(req): ApiJson<SignupRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), ApiError> {
    let email = validate::email(&req.email)?;
    let display_name = validate::display_name(&req.display_name)?;
    validate::password(&req.password)?;
    let icon = req
        .icon
        .as_deref()
        .map(|id| validate::icon(id, &st.config.user_icons).map(Icon::Preset))
        .transpose()?;
    let role = match req.role.unwrap_or(Role::Student) {
        Role::Admin => {
            return Err(ApiError::Validation(
                "role `admin` cannot be self-assigned".into(),
            ));
        }
        r => r,
    };

    let password_hash = st.passwords.hash(req.password).await?;
    let now = Utc::now();
    let user = User {
        id: Uuid::now_v7(), // time-ordered: nicer for logs and any future range scans
        email,
        display_name,
        icon,
        role,
        password_hash,
        created_at: now,
        updated_at: now,
    };
    st.repo.create_user(&user).await?;
    ::metrics::counter!("auth_signups_total").increment(1);
    tracing::info!(user_id = %user.id, "user signed up");

    let tokens = start_session(&st, &user, user_agent(&headers)).await?;
    Ok((
        StatusCode::CREATED,
        Json(AuthResponse {
            user: PublicUser::new(&user, &st.config.photo_public_base_url),
            tokens,
        }),
    ))
}

/// POST /v1/auth/login
pub async fn login(
    State(st): State<AppState>,
    headers: HeaderMap,
    ApiJson(req): ApiJson<LoginRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    // Same generic 401 for every failure mode: no account enumeration.
    if req.password.len() > 4 * validate::PASSWORD_MAX_CHARS {
        return Err(ApiError::Unauthorized);
    }
    let email = validate::normalize_email(&req.email);
    let user = st.repo.get_user_by_email(&email).await?;
    let stored_hash = user.as_ref().map(|u| u.password_hash.clone());
    // Always runs Argon2 (against a dummy hash if no user) so timing is uniform.
    let valid = st.passwords.verify(req.password, stored_hash).await?;

    let user = match (valid, user) {
        (true, Some(u)) => u,
        _ => {
            ::metrics::counter!("auth_login_failures_total").increment(1);
            return Err(ApiError::Unauthorized);
        }
    };

    ::metrics::counter!("auth_logins_total").increment(1);
    let tokens = start_session(&st, &user, user_agent(&headers)).await?;
    Ok(Json(AuthResponse {
        user: PublicUser::new(&user, &st.config.photo_public_base_url),
        tokens,
    }))
}

/// POST /v1/auth/refresh — exchange a refresh token for a new pair.
///
/// Refresh tokens rotate on every use. Presenting an already-rotated token is
/// treated as theft: the whole session is revoked, logging out both the
/// attacker and the legitimate device.
pub async fn refresh(
    State(st): State<AppState>,
    ApiJson(req): ApiJson<RefreshRequest>,
) -> Result<Json<TokenPair>, ApiError> {
    let parsed = tokens::parse(&req.refresh_token).ok_or(ApiError::Unauthorized)?;
    let session = st
        .repo
        .get_session(parsed.user_id, parsed.session_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;

    let now = Utc::now();
    if session.expires_at <= now {
        st.repo.delete_session(session.user_id, session.id).await?;
        return Err(ApiError::Unauthorized);
    }

    let presented_hash = tokens::hash_secret(&parsed.secret);
    if !tokens::hashes_match(&presented_hash, &session.token_hash) {
        tracing::warn!(
            user_id = %session.user_id,
            session_id = %session.id,
            "refresh token reuse detected; revoking session"
        );
        ::metrics::counter!("auth_refresh_reuse_detected_total").increment(1);
        st.repo.delete_session(session.user_id, session.id).await?;
        return Err(ApiError::Unauthorized);
    }

    let (new_secret, new_hash) = tokens::new_secret_and_hash();
    let new_expiry = now + Duration::seconds(st.config.refresh_token_ttl_secs);
    let rotated = st
        .repo
        .rotate_session(
            session.user_id,
            session.id,
            &session.token_hash,
            &new_hash,
            new_expiry,
        )
        .await?;
    if !rotated {
        // Lost a race with a concurrent refresh using the same token.
        return Err(ApiError::Unauthorized);
    }

    // Re-read the user so role changes / deletions take effect on refresh.
    let user = st
        .repo
        .get_user(session.user_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let (access_token, expires_in) = st.jwt.issue(&user)?;

    Ok(Json(TokenPair {
        access_token,
        refresh_token: tokens::encode(session.user_id, session.id, &new_secret),
        token_type: "Bearer",
        expires_in,
    }))
}

/// POST /v1/auth/logout — revoke the session behind a refresh token.
/// Idempotent: always 204, even for unknown tokens.
pub async fn logout(
    State(st): State<AppState>,
    ApiJson(req): ApiJson<RefreshRequest>,
) -> Result<StatusCode, ApiError> {
    if let Some(parsed) = tokens::parse(&req.refresh_token) {
        if let Some(session) = st
            .repo
            .get_session(parsed.user_id, parsed.session_id)
            .await?
        {
            if tokens::hashes_match(&tokens::hash_secret(&parsed.secret), &session.token_hash) {
                st.repo.delete_session(session.user_id, session.id).await?;
            }
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

/// POST /v1/auth/logout-all — revoke every session for the caller.
/// Outstanding access tokens remain valid until they expire (≤ ACCESS_TOKEN_TTL_SECS).
pub async fn logout_all(
    State(st): State<AppState>,
    AuthUser(claims): AuthUser,
) -> Result<StatusCode, ApiError> {
    st.repo.delete_all_sessions(claims.sub).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn start_session(
    st: &AppState,
    user: &User,
    user_agent: Option<String>,
) -> Result<TokenPair, ApiError> {
    let session_id = Uuid::new_v4();
    let (refresh_token, token_hash) = tokens::generate(user.id, session_id);
    let now = Utc::now();
    let session = Session {
        id: session_id,
        user_id: user.id,
        token_hash,
        created_at: now,
        expires_at: now + Duration::seconds(st.config.refresh_token_ttl_secs),
        user_agent,
    };
    st.repo.create_session(&session).await?;
    let (access_token, expires_in) = st.jwt.issue(user)?;
    Ok(TokenPair {
        access_token,
        refresh_token,
        token_type: "Bearer",
        expires_in,
    })
}

fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|ua| ua.chars().take(256).collect())
}
