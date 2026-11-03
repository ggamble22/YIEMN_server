//! The signed-in user's own profile.

use axum::{Json, extract::State};
use chrono::Utc;
use serde::Deserialize;

use crate::{
    auth::AuthUser, error::ApiError, models::PublicUser, routes::json::ApiJson, state::AppState,
    validate,
};

/// GET /v1/users/me
pub async fn me(
    State(st): State<AppState>,
    AuthUser(claims): AuthUser,
) -> Result<Json<PublicUser>, ApiError> {
    let user = st
        .repo
        .get_user(claims.sub)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json((&user).into()))
}

#[derive(Deserialize)]
pub struct UpdateMeRequest {
    pub display_name: String,
}

/// PATCH /v1/users/me
pub async fn update_me(
    State(st): State<AppState>,
    AuthUser(claims): AuthUser,
    ApiJson(req): ApiJson<UpdateMeRequest>,
) -> Result<Json<PublicUser>, ApiError> {
    let display_name = validate::display_name(&req.display_name)?;
    let user = st
        .repo
        .update_display_name(claims.sub, &display_name, Utc::now())
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json((&user).into()))
}
