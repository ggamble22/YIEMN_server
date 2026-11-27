//! End-to-end API tests against the in-memory repository.
//! Run with `cargo test`. No AWS or network access needed.

use std::sync::Arc;

use async_trait::async_trait;
use auth_service::{
    app,
    config::Config,
    media::{
        ModerationVerdict, Moderator, PhotoStore, moderation::NoModeration, store::MemoryPhotoStore,
    },
    models::Role,
    repo::memory::MemoryRepo,
    state::AppState,
};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

fn test_app() -> Router {
    test_app_with(|_| {})
}

fn test_app_with(customise: impl FnOnce(&mut Config)) -> Router {
    test_app_full(customise, Arc::new(NoModeration)).0
}

/// Also returns the photo store so tests can inspect what was stored.
fn test_app_full(
    customise: impl FnOnce(&mut Config),
    moderator: Arc<dyn Moderator>,
) -> (Router, Arc<MemoryPhotoStore>) {
    let mut config = Config::test_default();
    customise(&mut config);
    let photos = Arc::new(MemoryPhotoStore::default());
    let state = AppState::new(
        config,
        Arc::new(MemoryRepo::default()),
        photos.clone(),
        moderator,
    )
    .expect("state");
    (app(state), photos)
}

struct Req<'a> {
    method: &'a str,
    uri: &'a str,
    body: Option<Value>,
    bearer: Option<&'a str>,
    headers: Vec<(&'a str, &'a str)>,
}

impl<'a> Req<'a> {
    fn new(method: &'a str, uri: &'a str) -> Self {
        Self {
            method,
            uri,
            body: None,
            bearer: None,
            headers: Vec::new(),
        }
    }
    fn json(mut self, v: Value) -> Self {
        self.body = Some(v);
        self
    }
    fn bearer(mut self, t: &'a str) -> Self {
        self.bearer = Some(t);
        self
    }
    fn header(mut self, k: &'a str, v: &'a str) -> Self {
        self.headers.push((k, v));
        self
    }

    async fn send(self, app: &Router) -> (StatusCode, Value) {
        let mut b = Request::builder().method(self.method).uri(self.uri);
        if let Some(t) = self.bearer {
            b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        for (k, v) in self.headers {
            b = b.header(k, v);
        }
        let req = match self.body {
            Some(v) => b
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
        };
        (status, value)
    }
}

async fn signup(app: &Router, email: &str) -> Value {
    let (status, body) = Req::new("POST", "/v1/auth/signup")
        .json(json!({ "email": email, "password": "correct horse battery", "display_name": "Ada" }))
        .send(app)
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing `{key}` in {v}"))
}

#[tokio::test]
async fn health_endpoints() {
    let app = test_app();
    assert_eq!(
        Req::new("GET", "/healthz").send(&app).await.0,
        StatusCode::OK
    );
    assert_eq!(
        Req::new("GET", "/readyz").send(&app).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn signup_then_me() {
    let app = test_app();
    let body = signup(&app, "Ada@Example.com").await;
    assert_eq!(
        body["user"]["email"], "ada@example.com",
        "email is normalised"
    );
    assert_eq!(body["user"]["role"], "student");
    assert_eq!(body["token_type"], "Bearer");
    assert!(
        body["user"].get("password_hash").is_none(),
        "hash never leaks"
    );

    let (status, me) = Req::new("GET", "/v1/users/me")
        .bearer(s(&body, "access_token"))
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["id"], body["user"]["id"]);
}

#[tokio::test]
async fn duplicate_email_is_conflict_case_insensitively() {
    let app = test_app();
    signup(&app, "dup@example.com").await;
    let (status, body) = Req::new("POST", "/v1/auth/signup")
        .json(json!({ "email": "DUP@example.com", "password": "another password", "display_name": "B" }))
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "conflict");
}

#[tokio::test]
async fn signup_validation() {
    let app = test_app();
    let cases = [
        json!({ "email": "not-an-email", "password": "long enough", "display_name": "A" }),
        json!({ "email": "a@example.com", "password": "short", "display_name": "A" }),
        json!({ "email": "a@example.com", "password": "long enough", "display_name": "  " }),
        json!({ "email": "a@example.com", "password": "long enough", "display_name": "A", "role": "admin" }),
        json!({ "email": "a@example.com", "password": "long enough", "display_name": "A", "role": "wizard" }),
        json!({ "email": "a@example.com" }),
    ];
    for case in cases {
        let (status, body) = Req::new("POST", "/v1/auth/signup")
            .json(case.clone())
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "case {case} -> {body}");
        assert_eq!(body["error"]["code"], "validation_error");
    }
}

#[tokio::test]
async fn signup_accepts_allowed_roles() {
    let app = test_app();
    let (status, body) = Req::new("POST", "/v1/auth/signup")
        .json(json!({ "email": "t@example.com", "password": "long enough", "display_name": "T", "role": "educator" }))
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["user"]["role"], "educator");
}

#[tokio::test]
async fn login_success_and_generic_failures() {
    let app = test_app();
    signup(&app, "login@example.com").await;

    let (status, body) = Req::new("POST", "/v1/auth/login")
        .json(json!({ "email": " LOGIN@example.com ", "password": "correct horse battery" }))
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["access_token"].is_string());

    let (wrong_pw, b1) = Req::new("POST", "/v1/auth/login")
        .json(json!({ "email": "login@example.com", "password": "nope nope nope" }))
        .send(&app)
        .await;
    let (no_user, b2) = Req::new("POST", "/v1/auth/login")
        .json(json!({ "email": "ghost@example.com", "password": "nope nope nope" }))
        .send(&app)
        .await;
    assert_eq!(wrong_pw, StatusCode::UNAUTHORIZED);
    assert_eq!(no_user, StatusCode::UNAUTHORIZED);
    assert_eq!(b1, b2, "identical responses: no account enumeration");
}

#[tokio::test]
async fn protected_routes_require_valid_token() {
    let app = test_app();
    assert_eq!(
        Req::new("GET", "/v1/users/me").send(&app).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        Req::new("GET", "/v1/users/me")
            .bearer("garbage")
            .send(&app)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );

    // A token signed with a different secret is rejected.
    let other =
        test_app_with(|c| c.jwt_secret = "a-completely-different-secret-of-32+bytes".into());
    let body = signup(&other, "x@example.com").await;
    assert_eq!(
        Req::new("GET", "/v1/users/me")
            .bearer(s(&body, "access_token"))
            .send(&app)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn update_display_name() {
    let app = test_app();
    let body = signup(&app, "upd@example.com").await;
    let token = s(&body, "access_token");

    let (status, user) = Req::new("PATCH", "/v1/users/me")
        .bearer(token)
        .json(json!({ "display_name": "  Grace  " }))
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(user["display_name"], "Grace");

    let (_, me) = Req::new("GET", "/v1/users/me")
        .bearer(token)
        .send(&app)
        .await;
    assert_eq!(me["display_name"], "Grace");
}

#[tokio::test]
async fn icon_is_optional_and_null_by_default() {
    let app = test_app();
    let body = signup(&app, "noicon@example.com").await;
    assert!(body["user"]["icon"].is_null());
}

#[tokio::test]
async fn icons_endpoint_lists_choices() {
    let app = test_app();
    let (status, body) = Req::new("GET", "/v1/users/icons").send(&app).await;
    assert_eq!(status, StatusCode::OK);
    let icons = body["icons"].as_array().unwrap();
    assert!(icons.iter().any(|i| i == "fox"));
}

#[tokio::test]
async fn signup_with_icon() {
    let app = test_app();
    let (status, body) = Req::new("POST", "/v1/auth/signup")
        .json(json!({ "email": "icon@example.com", "password": "long enough", "display_name": "I", "icon": "Owl" }))
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["user"]["icon"]["type"], "preset");
    assert_eq!(body["user"]["icon"]["id"], "owl", "icon id is normalised");

    let (status, body) = Req::new("POST", "/v1/auth/signup")
        .json(json!({ "email": "bad@example.com", "password": "long enough", "display_name": "B", "icon": "not-a-real-icon" }))
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "validation_error");
}

#[tokio::test]
async fn set_change_and_clear_icon() {
    let app = test_app();
    let body = signup(&app, "seticon@example.com").await;
    let token = s(&body, "access_token");
    let patch = |v: Value| {
        let app = app.clone();
        let token = token.to_string();
        async move {
            Req::new("PATCH", "/v1/users/me")
                .bearer(&token)
                .json(v)
                .send(&app)
                .await
        }
    };

    let (status, user) = patch(json!({ "icon": "fox" })).await;
    assert_eq!(status, StatusCode::OK, "{user}");
    assert_eq!(user["icon"], json!({ "type": "preset", "id": "fox" }));
    assert_eq!(user["display_name"], "Ada", "display_name untouched");

    // Changing only the name leaves the icon alone.
    let (_, user) = patch(json!({ "display_name": "Grace" })).await;
    assert_eq!(user["icon"]["id"], "fox");

    let (status, _) = patch(json!({ "icon": "unicorn-laser" })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Explicit null removes it.
    let (status, user) = patch(json!({ "icon": null })).await;
    assert_eq!(status, StatusCode::OK);
    assert!(user["icon"].is_null());

    let (_, me) = Req::new("GET", "/v1/users/me")
        .bearer(token)
        .send(&app)
        .await;
    assert!(me["icon"].is_null());
    assert_eq!(me["display_name"], "Grace");

    // An empty patch is rejected.
    let (status, _) = patch(json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn icon_set_is_configurable() {
    let app = test_app_with(|c| c.user_icons = vec!["school-bus".into()]);
    let (status, body) = Req::new("GET", "/v1/users/icons").send(&app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["icons"], json!(["school-bus"]));
}

#[tokio::test]
async fn refresh_rotates_and_detects_reuse() {
    let app = test_app();
    let body = signup(&app, "rot@example.com").await;
    let first = s(&body, "refresh_token").to_string();

    let (status, pair) = Req::new("POST", "/v1/auth/refresh")
        .json(json!({ "refresh_token": first }))
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::OK, "{pair}");
    let second = s(&pair, "refresh_token").to_string();
    assert_ne!(first, second, "token rotated");
    assert_eq!(
        Req::new("GET", "/v1/users/me")
            .bearer(s(&pair, "access_token"))
            .send(&app)
            .await
            .0,
        StatusCode::OK
    );

    // Replaying the old token = theft signal: rejected, and the session is revoked...
    let (status, _) = Req::new("POST", "/v1/auth/refresh")
        .json(json!({ "refresh_token": first }))
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // ...so even the legitimate newest token no longer works.
    let (status, _) = Req::new("POST", "/v1/auth/refresh")
        .json(json!({ "refresh_token": second }))
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_rejects_malformed_and_expired() {
    let app = test_app();
    for bad in ["", "nope", "a.b.c"] {
        let (status, _) = Req::new("POST", "/v1/auth/refresh")
            .json(json!({ "refresh_token": bad }))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{bad}");
    }

    let expired_app = test_app_with(|c| c.refresh_token_ttl_secs = -1);
    let body = signup(&expired_app, "exp@example.com").await;
    let (status, _) = Req::new("POST", "/v1/auth/refresh")
        .json(json!({ "refresh_token": s(&body, "refresh_token") }))
        .send(&expired_app)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_revokes_only_that_session() {
    let app = test_app();
    let a = signup(&app, "out@example.com").await;
    let (_, b) = Req::new("POST", "/v1/auth/login")
        .json(json!({ "email": "out@example.com", "password": "correct horse battery" }))
        .send(&app)
        .await;

    let (status, _) = Req::new("POST", "/v1/auth/logout")
        .json(json!({ "refresh_token": s(&a, "refresh_token") }))
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let refresh = |t: String| {
        let app = app.clone();
        async move {
            Req::new("POST", "/v1/auth/refresh")
                .json(json!({ "refresh_token": t }))
                .send(&app)
                .await
                .0
        }
    };
    assert_eq!(
        refresh(s(&a, "refresh_token").into()).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(refresh(s(&b, "refresh_token").into()).await, StatusCode::OK);

    // Logout is idempotent.
    let (status, _) = Req::new("POST", "/v1/auth/logout")
        .json(json!({ "refresh_token": "not-a-token" }))
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn logout_all_revokes_every_session() {
    let app = test_app();
    let a = signup(&app, "all@example.com").await;
    let (_, b) = Req::new("POST", "/v1/auth/login")
        .json(json!({ "email": "all@example.com", "password": "correct horse battery" }))
        .send(&app)
        .await;

    let (status, _) = Req::new("POST", "/v1/auth/logout-all")
        .bearer(s(&a, "access_token"))
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    for token in [s(&a, "refresh_token"), s(&b, "refresh_token")] {
        let (status, _) = Req::new("POST", "/v1/auth/refresh")
            .json(json!({ "refresh_token": token }))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn credential_endpoints_are_rate_limited_per_ip() {
    let app = test_app_with(|c| {
        c.rate_limit_per_minute = 3;
        c.trust_forwarded_for = true;
    });
    let attempt = |ip: &'static str| {
        let app = app.clone();
        async move {
            Req::new("POST", "/v1/auth/login")
                .header("x-forwarded-for", ip)
                .json(json!({ "email": "x@example.com", "password": "whatever123" }))
                .send(&app)
                .await
        }
    };

    for _ in 0..3 {
        assert_eq!(attempt("203.0.113.7").await.0, StatusCode::UNAUTHORIZED);
    }
    let (status, body) = attempt("203.0.113.7").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"]["code"], "rate_limited");
    // A different client is unaffected.
    assert_eq!(attempt("198.51.100.9").await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn malformed_json_gets_standard_error_shape() {
    let app = test_app();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{not json"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["error"]["code"], "validation_error");
}

// ---------- photo icons ----------

fn png(w: u32, h: u32) -> Vec<u8> {
    let img = image::RgbaImage::from_pixel(w, h, image::Rgba([30, 120, 200, 255]));
    let mut out = Vec::new();
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
        .unwrap();
    out
}

async fn upload(app: &Router, token: &str, bytes: Vec<u8>) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("PUT")
        .uri("/v1/users/me/photo")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "image/png")
        .body(Body::from(bytes))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

async fn get_raw(app: &Router, uri: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, bytes)
}

fn photo_url(user: &Value) -> String {
    assert_eq!(user["icon"]["type"], "photo", "{user}");
    user["icon"]["url"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn upload_photo_sets_icon_and_serves_safe_jpeg() {
    let (app, _) = test_app_full(|_| {}, Arc::new(NoModeration));
    let body = signup(&app, "photo@example.com").await;
    let token = s(&body, "access_token");

    let (status, user) = upload(&app, token, png(640, 480)).await;
    assert_eq!(status, StatusCode::OK, "{user}");
    let url = photo_url(&user);
    assert!(url.starts_with("/v1/photos/avatars/"), "{url}");

    let (status, headers, bytes) = get_raw(&app, &url).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "image/jpeg");
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    let img = image::load_from_memory(&bytes).unwrap();
    assert_eq!((img.width(), img.height()), (256, 256), "cropped + resized");

    // /me reflects it too.
    let (_, me) = Req::new("GET", "/v1/users/me")
        .bearer(token)
        .send(&app)
        .await;
    assert_eq!(photo_url(&me), url);
}

#[tokio::test]
async fn replacing_or_clearing_a_photo_deletes_the_old_one() {
    let (app, store) = test_app_full(|_| {}, Arc::new(NoModeration));
    let body = signup(&app, "replace@example.com").await;
    let token = s(&body, "access_token");

    let (_, first) = upload(&app, token, png(300, 300)).await;
    let first_url = photo_url(&first);
    let (_, second) = upload(&app, token, png(400, 300)).await;
    let second_url = photo_url(&second);
    assert_ne!(first_url, second_url, "every upload gets a fresh key");
    assert_eq!(get_raw(&app, &first_url).await.0, StatusCode::NOT_FOUND);
    assert_eq!(get_raw(&app, &second_url).await.0, StatusCode::OK);

    // Switching to a preset removes the photo.
    let (status, user) = Req::new("PATCH", "/v1/users/me")
        .bearer(token)
        .json(json!({ "icon": "owl" }))
        .send(&app)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(user["icon"], json!({ "type": "preset", "id": "owl" }));
    assert_eq!(get_raw(&app, &second_url).await.0, StatusCode::NOT_FOUND);

    // Upload again, then clear with null.
    let (_, third) = upload(&app, token, png(300, 300)).await;
    let third_url = photo_url(&third);
    let key = third_url.trim_start_matches("/v1/photos/").to_string();
    assert!(store.get(&key).await.unwrap().is_some());
    let (_, user) = Req::new("PATCH", "/v1/users/me")
        .bearer(token)
        .json(json!({ "icon": null }))
        .send(&app)
        .await;
    assert!(user["icon"].is_null());
    assert!(store.get(&key).await.unwrap().is_none());
}

#[tokio::test]
async fn upload_rejects_bad_input() {
    let app = test_app_with(|c| c.photo_max_bytes = 50_000);
    let body = signup(&app, "badphoto@example.com").await;
    let token = s(&body, "access_token");

    let (status, err) = upload(&app, token, b"<svg onload=alert(1)>".to_vec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
    assert_eq!(err["error"]["code"], "validation_error");

    let (status, _) = upload(&app, token, Vec::new()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = upload(&app, token, png(20, 20)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "too small");

    let (status, err) = upload(&app, token, vec![0u8; 60_000]).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(err["error"]["code"], "payload_too_large");

    // Unauthenticated.
    let req = Request::builder()
        .method("PUT")
        .uri("/v1/users/me/photo")
        .body(Body::from(png(100, 100)))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

struct RejectEverything;

#[async_trait]
impl Moderator for RejectEverything {
    async fn check(&self, _jpeg: &[u8]) -> anyhow::Result<ModerationVerdict> {
        Ok(ModerationVerdict::Rejected(vec!["Test Label".into()]))
    }
}

#[tokio::test]
async fn moderation_rejection_stores_nothing() {
    let (app, _) = test_app_full(|_| {}, Arc::new(RejectEverything));
    let body = signup(&app, "flagged@example.com").await;
    let token = s(&body, "access_token");

    let (status, err) = upload(&app, token, png(300, 300)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(err["error"]["code"], "photo_rejected");
    assert!(
        !err.to_string().contains("Test Label"),
        "labels never leak to the client"
    );

    let (_, me) = Req::new("GET", "/v1/users/me")
        .bearer(token)
        .send(&app)
        .await;
    assert!(me["icon"].is_null());
}

#[tokio::test]
async fn photo_uploads_can_be_restricted_by_role() {
    let app = test_app_with(|c| c.photo_icon_roles = vec![Role::Parent, Role::Educator]);
    let student = signup(&app, "kid@example.com").await;
    let (status, err) = upload(&app, s(&student, "access_token"), png(300, 300)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(err["error"]["code"], "forbidden");

    let (_, parent) = Req::new("POST", "/v1/auth/signup")
        .json(json!({ "email": "mum@example.com", "password": "long enough", "display_name": "M", "role": "parent" }))
        .send(&app)
        .await;
    let (status, _) = upload(&app, s(&parent, "access_token"), png(300, 300)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn photo_route_rejects_invalid_keys() {
    let app = test_app();
    for uri in [
        "/v1/photos/avatars/../x.jpg",
        "/v1/photos/secret.txt",
        "/v1/photos/avatars/missing.jpg",
    ] {
        assert_eq!(get_raw(&app, uri).await.0, StatusCode::NOT_FOUND, "{uri}");
    }
}
