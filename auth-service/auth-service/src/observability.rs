//! Logging and Prometheus setup.

use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use tracing_subscriber::EnvFilter;

use crate::config::LogFormat;

pub fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info,tower_http=info,aws_config=warn,aws_smithy_runtime=warn")
    });
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    match format {
        // One JSON object per line: what CloudWatch / Loki / Datadog want.
        LogFormat::Json => builder.json().init(),
        LogFormat::Pretty => builder.init(),
    }
}

pub fn install_metrics_recorder() -> anyhow::Result<PrometheusHandle> {
    const LATENCY_BUCKETS: &[f64] = &[
        0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
    ];
    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full("http_request_duration_seconds".to_string()),
            LATENCY_BUCKETS,
        )?
        .install_recorder()?;
    Ok(handle)
}
