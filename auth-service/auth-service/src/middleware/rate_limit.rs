//! Per-client-IP fixed-window rate limiting for credential endpoints.
//!
//! This is a per-pod limiter: with N replicas a client gets up to N× the limit.
//! It exists to blunt brute-force/credential-stuffing at the app layer; put a
//! global limit at the edge too (ingress / WAF) — see README.

use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;

use crate::{error::ApiError, state::AppState};

pub struct RateLimiter {
    limit: u32,
    window: Duration,
    buckets: DashMap<IpAddr, Window>,
}

struct Window {
    started: Instant,
    count: u32,
}

impl RateLimiter {
    /// `limit == 0` disables limiting.
    pub fn per_minute(limit: u32) -> Self {
        Self {
            limit,
            window: Duration::from_secs(60),
            buckets: DashMap::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.limit > 0
    }

    /// Record a hit; returns `false` if the client is over its limit.
    pub fn check(&self, ip: IpAddr) -> bool {
        if !self.is_enabled() {
            return true;
        }
        let now = Instant::now();
        let mut w = self.buckets.entry(ip).or_insert(Window {
            started: now,
            count: 0,
        });
        if now.duration_since(w.started) >= self.window {
            w.started = now;
            w.count = 0;
        }
        if w.count >= self.limit {
            false
        } else {
            w.count += 1;
            true
        }
    }

    /// Drop expired windows so memory stays bounded. Call periodically.
    pub fn purge_expired(&self) {
        let now = Instant::now();
        self.buckets
            .retain(|_, w| now.duration_since(w.started) < self.window);
    }
}

pub async fn rate_limit(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if state.limiter.is_enabled() {
        if let Some(ip) = client_ip(&req, state.config.trust_forwarded_for) {
            if !state.limiter.check(ip) {
                ::metrics::counter!("auth_rate_limited_total").increment(1);
                return ApiError::TooManyRequests.into_response();
            }
        }
    }
    next.run(req).await
}

fn client_ip(req: &Request, trust_forwarded_for: bool) -> Option<IpAddr> {
    if trust_forwarded_for {
        // Right-most entry = the address our trusted proxy saw. Left-most
        // entries are client-supplied and trivially spoofable.
        let forwarded = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|ip| ip.trim().parse().ok());
        if forwarded.is_some() {
            return forwarded;
        }
    }
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_then_resets_per_ip() {
        let rl = RateLimiter::per_minute(2);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(rl.check(a));
        assert!(rl.check(a));
        assert!(!rl.check(a));
        assert!(rl.check(b), "other clients unaffected");
    }

    #[test]
    fn disabled_when_zero() {
        let rl = RateLimiter::per_minute(0);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        assert!((0..1000).all(|_| rl.check(a)));
    }
}
