//! One shared AWS SDK configuration (credentials, region, timeouts, retries)
//! for every AWS client the service uses.

use std::time::Duration;

use aws_config::{BehaviorVersion, SdkConfig, retry::RetryConfig, timeout::TimeoutConfig};

/// Load from the standard credential chain (IRSA / Pod Identity in EKS, env
/// vars locally) with tight timeouts suited to small, latency-sensitive calls.
pub async fn load() -> SdkConfig {
    aws_config::defaults(BehaviorVersion::latest())
        .timeout_config(
            TimeoutConfig::builder()
                .connect_timeout(Duration::from_secs(1))
                .operation_attempt_timeout(Duration::from_secs(2))
                .operation_timeout(Duration::from_secs(5))
                .build(),
        )
        .retry_config(RetryConfig::standard().with_max_attempts(3))
        .load()
        .await
}

/// Image moderation can take longer than a key-value read.
pub fn slow_call_timeouts() -> TimeoutConfig {
    TimeoutConfig::builder()
        .connect_timeout(Duration::from_secs(1))
        .operation_attempt_timeout(Duration::from_secs(5))
        .operation_timeout(Duration::from_secs(10))
        .build()
}
