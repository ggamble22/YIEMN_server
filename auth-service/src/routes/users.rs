//! The signed-in user's own profile, icon and photo.

use axum::{
    Json,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    error::ApiError,
    media::{
        ModerationVerdict,
        photo::{self, PhotoError},
        store::{PHOTO_CACHE_CONTROL, PHOTO_CONTENT_TYPE},
    },
    models::{Icon, PublicUser, User},
    repo::ProfileUpdate,
    routes::json::ApiJson,
    state::AppState,
    validate,
};

/// Photo object keys look like `avatars/<user uuid>/<random uuid>.jpg`.
const PHOTO_KEY_PREFIX: &str = "avatars/";

fn public(st: &AppState, user: &User) -> PublicUser {
    PublicUser::new(user, &st.config.photo_public_base_url)
}

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
    Ok(Json(public(&st, &user)))
}

/// Partial update: omitted fields are unchanged.
#[derive(Deserialize)]
pub struct UpdateMeRequest {
    #[serde(default)]
    pub display_name: Option<String>,
    /// Omitted = unchanged, `null` = remove the icon (preset or photo),
    /// `"fox"` = switch to that preset. Photos are set via `PUT /me/photo`.
    #[serde(default, deserialize_with = "present_or_null")]
    pub icon: Option<Option<String>>,
}

/// Lets serde tell "field missing" (outer `None`, via `default`) apart from
/// "field is null" (`Some(None)`).
fn present_or_null<'de, D, T>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(de).map(Some)
}

/// PATCH /v1/users/me
pub async fn update_me(
    State(st): State<AppState>,
    AuthUser(claims): AuthUser,
    ApiJson(req): ApiJson<UpdateMeRequest>,
) -> Result<Json<PublicUser>, ApiError> {
    let update = ProfileUpdate {
        display_name: req
            .display_name
            .as_deref()
            .map(validate::display_name)
            .transpose()?,
        icon: match req.icon {
            Some(Some(id)) => Some(Some(Icon::Preset(validate::icon(
                &id,
                &st.config.user_icons,
            )?))),
            Some(None) => Some(None),
            None => None,
        },
    };
    if update.is_empty() {
        return Err(ApiError::Validation(
            "provide at least one of `display_name` or `icon`".into(),
        ));
    }
    let user = apply_update(&st, claims.sub, &update).await?;
    Ok(Json(public(&st, &user)))
}

/// PUT /v1/users/me/photo — raw image bytes as the body (JPEG, PNG or WebP).
///
/// The image is re-encoded (stripping location and other metadata), cropped to
/// a 256×256 square, screened for unsafe content, stored, and set as the icon.
pub async fn upload_photo(
    State(st): State<AppState>,
    AuthUser(claims): AuthUser,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<PublicUser>, ApiError> {
    if !st.config.photo_icon_roles.contains(&claims.role) {
        return Err(ApiError::Forbidden(
            "photo icons aren't available for this account; choose a preset icon".into(),
        ));
    }
    let body = body.map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::PayloadTooLarge
        } else {
            ApiError::Validation(rejection.body_text())
        }
    })?;
    if body.is_empty() {
        return Err(ApiError::Validation(
            "send the image file as the request body".into(),
        ));
    }

    // 1. Decode + re-encode, bounded by the per-pod job semaphore.
    let jpeg = {
        let _permit = st
            .photo_jobs
            .acquire()
            .await
            .map_err(|_| ApiError::Unavailable)?;
        tokio::task::spawn_blocking(move || photo::process_avatar(&body))
            .await
            .map_err(anyhow::Error::from)?
            .map_err(|e: PhotoError| ApiError::Validation(e.to_string()))?
    };

    // 2. Screen before it is stored or visible to anyone.
    match st.moderator.check(&jpeg).await? {
        ModerationVerdict::Approved => {}
        ModerationVerdict::Rejected(labels) => {
            ::metrics::counter!("photo_uploads_rejected_total").increment(1);
            tracing::warn!(user_id = %claims.sub, ?labels, "photo rejected by moderation");
            return Err(ApiError::PhotoRejected);
        }
    }

    // 3. Store under a fresh, unguessable key, then point the profile at it.
    let key = format!("{PHOTO_KEY_PREFIX}{}/{}.jpg", claims.sub, Uuid::new_v4());
    st.photos.put(&key, jpeg).await?;
    let update = ProfileUpdate {
        icon: Some(Some(Icon::Photo { key: key.clone() })),
        ..Default::default()
    };
    let user = match apply_update(&st, claims.sub, &update).await {
        Ok(user) => user,
        Err(err) => {
            delete_photo_best_effort(&st, &key).await; // don't leave an orphan
            return Err(err);
        }
    };
    ::metrics::counter!("photo_uploads_total").increment(1);
    Ok(Json(public(&st, &user)))
}

/// GET /v1/photos/{*key} — serve a stored photo. Public by design (avatars are
/// shown to other users); keys are random so photos can't be enumerated.
/// Put a CDN in front of this path in production.
pub async fn get_photo(
    State(st): State<AppState>,
    Path(key): Path<String>,
) -> Result<Response, ApiError> {
    if !is_valid_photo_key(&key) {
        return Err(ApiError::NotFound);
    }
    let bytes = st.photos.get(&key).await?.ok_or(ApiError::NotFound)?;
    Ok((
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(PHOTO_CONTENT_TYPE),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static(PHOTO_CACHE_CONTROL),
            ),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
        ],
        bytes,
    )
        .into_response())
}

#[derive(Serialize)]
pub struct IconsResponse {
    pub icons: Vec<String>,
    /// Whether any role may upload a photo (`PUT /v1/users/me/photo`).
    pub photo_upload_enabled: bool,
}

/// GET /v1/users/icons — the preset icon ids users can pick from. Public, so
/// the signup screen can show the picker before an account exists.
pub async fn icons(State(st): State<AppState>) -> Json<IconsResponse> {
    Json(IconsResponse {
        icons: st.config.user_icons.clone(),
        photo_upload_enabled: !st.config.photo_icon_roles.is_empty(),
    })
}

/// Apply a profile update and, if a previous photo was replaced or removed,
/// delete it from storage.
async fn apply_update(
    st: &AppState,
    user_id: Uuid,
    update: &ProfileUpdate,
) -> Result<User, ApiError> {
    let previous_photo = if update.icon.is_some() {
        st.repo
            .get_user(user_id)
            .await?
            .and_then(|u| u.icon)
            .and_then(|icon| icon.photo_key().map(str::to_string))
    } else {
        None
    };

    let user = st
        .repo
        .update_profile(user_id, update, Utc::now())
        .await?
        .ok_or(ApiError::NotFound)?;

    if let Some(old) = previous_photo {
        let still_used = user.icon.as_ref().and_then(Icon::photo_key) == Some(old.as_str());
        if !still_used {
            delete_photo_best_effort(st, &old).await;
        }
    }
    Ok(user)
}

/// A failed delete leaves an unreferenced object, not a broken profile, so log
/// and move on. (An S3 inventory/lifecycle sweep can clean stragglers.)
async fn delete_photo_best_effort(st: &AppState, key: &str) {
    if let Err(err) = st.photos.delete(key).await {
        tracing::warn!(error = %err, key, "failed to delete old photo");
    }
}

fn is_valid_photo_key(key: &str) -> bool {
    key.len() <= 128
        && key.starts_with(PHOTO_KEY_PREFIX)
        && key.ends_with(".jpg")
        && !key.contains("..")
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn photo_keys() {
        assert!(is_valid_photo_key(&format!(
            "avatars/{}/{}.jpg",
            Uuid::nil(),
            Uuid::new_v4()
        )));
        for bad in [
            "",
            "avatars/../secret.jpg",
            "other/x.jpg",
            "avatars/x.png",
            "avatars/a b.jpg",
        ] {
            assert!(!is_valid_photo_key(bad), "{bad}");
        }
    }
}
