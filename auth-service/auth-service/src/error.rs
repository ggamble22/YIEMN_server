//! A single error type for handlers, rendered as a consistent JSON body:
//! `{"error": {"code": "...", "message": "..."}}`.

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::repo::RepoError;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    Validation(String),
    #[error("invalid credentials or token")]
    Unauthorized,
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Conflict(String),
    #[error("too many requests, slow down")]
    TooManyRequests,
    #[error("service temporarily unavailable")]
    Unavailable,
    #[error("internal server error")]
    Internal(#[from] anyhow::Error),
}

impl ApiError {
    fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::Validation(_) => (StatusCode::BAD_REQUEST, "validation_error"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            Self::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_and_code();
        if let Self::Internal(ref err) = self {
            // Full detail goes to logs only; clients get a generic message.
            tracing::error!(error = ?err, "internal error");
        }
        let body = Json(json!({ "error": { "code": code, "message": self.to_string() } }));
        let mut resp = (status, body).into_response();
        match self {
            Self::Unauthorized => {
                resp.headers_mut()
                    .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            }
            Self::TooManyRequests => {
                resp.headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
            }
            _ => {}
        }
        resp
    }
}

impl From<RepoError> for ApiError {
    fn from(err: RepoError) -> Self {
        match err {
            RepoError::EmailTaken => {
                Self::Conflict("an account with this email already exists".into())
            }
            RepoError::Other(e) => Self::Internal(e),
        }
    }
}
