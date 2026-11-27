use std::{net::SocketAddr, sync::Arc, time::Duration};

use auth_service::{
    app, aws,
    config::{Config, PhotoModeration, PhotoStorage, StorageBackend},
    media::{
        Moderator, PhotoStore,
        moderation::{NoModeration, RekognitionModerator},
        store::{MemoryPhotoStore, S3PhotoStore},
    },
    observability,
    repo::{Repo, dynamo::DynamoRepo, memory::MemoryRepo},
    state::AppState,
    tls,
};
use axum::{Router, routing::get};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_env()?;
    observability::init_tracing(config.log_format);
    let metrics = observability::install_metrics_recorder()?;

    let uses_aws = config.storage == StorageBackend::DynamoDb
        || config.photo_storage == PhotoStorage::S3
        || config.photo_moderation == PhotoModeration::Rekognition;
    let shared_aws = if uses_aws {
        Some(aws::load().await)
    } else {
        None
    };
    let aws_cfg = || {
        shared_aws
            .as_ref()
            .expect("AWS config loaded when an AWS backend is selected")
    };

    let repo: Arc<dyn Repo> = match config.storage {
        StorageBackend::DynamoDb => Arc::new(DynamoRepo::from_config(aws_cfg(), &config)),
        StorageBackend::Memory => {
            tracing::warn!(
                "using in-memory storage: data is NOT persisted or shared between replicas"
            );
            Arc::new(MemoryRepo::default())
        }
    };

    let photos: Arc<dyn PhotoStore> = match config.photo_storage {
        PhotoStorage::S3 => {
            let mut builder = aws_sdk_s3::config::Builder::from(aws_cfg());
            if let Some(endpoint) = &config.s3_endpoint {
                builder = builder.endpoint_url(endpoint).force_path_style(true);
            }
            Arc::new(S3PhotoStore::new(
                aws_sdk_s3::Client::from_conf(builder.build()),
                &config.photo_bucket,
            ))
        }
        PhotoStorage::Memory => {
            tracing::warn!("using in-memory photo storage: photos are NOT persisted");
            Arc::new(MemoryPhotoStore::default())
        }
    };

    let moderator: Arc<dyn Moderator> = match config.photo_moderation {
        PhotoModeration::Rekognition => {
            let rek_config = aws_sdk_rekognition::config::Builder::from(aws_cfg())
                .timeout_config(aws::slow_call_timeouts())
                .build();
            Arc::new(RekognitionModerator::new(
                aws_sdk_rekognition::Client::from_conf(rek_config),
                config.photo_moderation_min_confidence,
            ))
        }
        PhotoModeration::Off => {
            tracing::warn!("photo moderation is OFF: uploaded photos are not screened");
            Arc::new(NoModeration)
        }
    };

    let state = AppState::new(config.clone(), repo, photos, moderator)?;

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

    let service = app(state).into_make_service_with_connect_info::<SocketAddr>();

    match tls::server_config(&config.tls).await? {
        Some(tls_config) => {
            if matches!(config.tls, tls::TlsMode::SelfSigned { .. }) {
                tracing::warn!(
                    "serving HTTPS with a SELF-SIGNED certificate: for local development only"
                );
            }
            tracing::info!(
                addr = %config.bind_addr,
                metrics = %config.metrics_addr,
                "auth-service listening (HTTPS)"
            );
            let handle = axum_server::Handle::new();
            let shutdown = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                // Let in-flight requests finish, within Kubernetes' grace period.
                shutdown.graceful_shutdown(Some(Duration::from_secs(20)));
            });
            axum_server::bind_rustls(config.bind_addr, tls_config)
                .handle(handle)
                .serve(service)
                .await?;
        }
        None => {
            let listener = TcpListener::bind(config.bind_addr).await?;
            tracing::info!(
                addr = %config.bind_addr,
                metrics = %config.metrics_addr,
                "auth-service listening (HTTP)"
            );
            axum::serve(listener, service)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        }
    }

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
