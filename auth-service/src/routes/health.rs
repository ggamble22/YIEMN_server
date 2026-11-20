//! Kubernetes probes.
//! - `/healthz` (liveness): the process is up. Never touches dependencies, so a
//!   DynamoDB blip doesn't cause a restart storm.
//! - `/readyz` (readiness): we can reach DynamoDB; otherwise stop routing traffic here.

use std::time::Duration;

use axum::{Json, extract::State, http::StatusCode};
use serde_json::{Value, json};

use crate::state::AppState;

pub async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

pub async fn readyz(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    match tokio::time::timeout(Duration::from_secs(2), state.repo.ping()).await {
        Ok(Ok(())) => (StatusCode::OK, Json(json!({ "status": "ready" }))),
        Ok(Err(err)) => {
            tracing::warn!(error = %err, "readiness check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "unavailable" })),
            )
        }
        Err(_) => {
            tracing::warn!("readiness check timed out");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "timeout" })),
            )
        }
    }
}
