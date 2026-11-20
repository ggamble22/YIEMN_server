//! User accounts + authentication service.
//!
//! The crate is a library so the HTTP app can be built in-process by
//! integration tests (see `tests/api.rs`); `main.rs` is a thin launcher.

pub mod auth;
pub mod aws;
pub mod config;
pub mod error;
pub mod media;
pub mod middleware;
pub mod models;
pub mod observability;
pub mod repo;
pub mod routes;
pub mod state;
pub mod validate;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{Method, header},
    middleware as axum_mw,
    routing::{get, post, put},
};
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

use crate::state::AppState;

/// Maximum accepted request body. Auth payloads are tiny; this blocks abuse.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Build the public HTTP application.
#[allow(deprecated)] // `TimeoutLayer::new` is deprecated in newer tower-http patch releases.
pub fn app(state: AppState) -> Router {
    // Unauthenticated, credential-accepting endpoints are rate limited per client IP.
    let auth_routes = Router::new()
        .route("/signup", post(routes::auth::signup))
        .route("/login", post(routes::auth::login))
        .route("/refresh", post(routes::auth::refresh))
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::rate_limit::rate_limit,
        ))
        .route("/logout", post(routes::auth::logout))
        .route("/logout-all", post(routes::auth::logout_all));

    let user_routes = Router::new()
        .route(
            "/me",
            get(routes::users::me).patch(routes::users::update_me),
        )
        .route("/icons", get(routes::users::icons))
        .route(
            "/me/photo",
            // Route-level limit overrides the small global one below.
            put(routes::users::upload_photo)
                .layer(DefaultBodyLimit::max(state.config.photo_max_bytes)),
        );

    let api_v1 = Router::new()
        .nest("/auth", auth_routes)
        .nest("/users", user_routes)
        .route("/photos/{*key}", get(routes::users::get_photo));

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(state.config.cors_allowed_origins.clone()))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);

    Router::new()
        .route("/healthz", get(routes::health::healthz))
        .route("/readyz", get(routes::health::readyz))
        .nest("/v1", api_v1)
        // route_layer so the matched route template (not the raw path) is the metric label.
        .route_layer(axum_mw::from_fn(middleware::metrics::track_metrics))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(
            ServiceBuilder::new()
                .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
                .layer(TraceLayer::new_for_http())
                .layer(PropagateRequestIdLayer::x_request_id())
                .layer(TimeoutLayer::new(state.config.request_timeout))
                .layer(cors),
        )
        .with_state(state)
}
