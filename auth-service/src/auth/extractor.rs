//! `AuthUser` extractor: add it to a handler's arguments to require a valid
//! `Authorization: Bearer <access token>` header.

use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};

use crate::{auth::jwt::Claims, error::ApiError, state::AppState};

pub struct AuthUser(pub Claims);

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let value = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(ApiError::Unauthorized)?;
        let token = value
            .strip_prefix("Bearer ")
            .or_else(|| value.strip_prefix("bearer "))
            .ok_or(ApiError::Unauthorized)?;
        let claims = state
            .jwt
            .verify(token.trim())
            .map_err(|_| ApiError::Unauthorized)?;
        Ok(Self(claims))
    }
}
