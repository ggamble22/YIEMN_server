use std::{net::SocketAddr, sync::Arc, time::Duration};

use auth_service::{
    app,
    config::{Config, StorageBackend},
    observability,
    repo::{Repo, dynamo::DynamoRepo, memory::MemoryRepo},
    state::AppState,
};
use axum::{Router, routing::get};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_env()?;
    observability::init_tracing(config.log_format);
    let metrics = observability::install_metrics_recorder()?;

    let repo: Arc<dyn Repo> = match config.storage {
        StorageBackend::DynamoDb => Arc::new(DynamoRepo::from_config(&config).await),
        StorageBackend::Memory => {
            tracing::warn!(
                "using in-memory storage: data is NOT persisted or shared between replicas"
            );
            Arc::new(MemoryRepo::default())
        }
    };

    let state = AppState::new(config.clone(), repo)?;

    // Keep the rate limiter's memory bounded.
    let limiter = state.limiter.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            limiter.purge_expired();
        }
    });

    // Metrics on a separate port so they're never exposed through the public ingress.
    let metrics_app = Router::new().route(
        "/metrics",
        get(move || {
            let metrics = metrics.clone();
            async move { metrics.render() }
        }),
    );
    let metrics_listener = TcpListener::bind(config.metrics_addr).await?;
    tokio::spawn(async move {
        if let Err(err) = axum::serve(metrics_listener, metrics_app).await {
            tracing::error!(error = %err, "metrics server stopped");
        }
    });

    let listener = TcpListener::bind(config.bind_addr).await?;
    tracing::info!(addr = %config.bind_addr, metrics = %config.metrics_addr, "auth-service listening");

    axum::serve(
        listener,
        app(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    tracing::info!("shut down cleanly");
    Ok(())
}

/// Resolve on Ctrl-C or SIGTERM (what Kubernetes sends) so in-flight requests finish.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received, draining connections");
}
