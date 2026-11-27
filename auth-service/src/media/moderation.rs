//! Automated screening of uploaded photos before anyone else can see them.
//!
//! On a platform used by children this is the minimum bar, not a complete
//! answer: automated moderation misses things, so pair it with a way for users
//! to report a photo and for staff to remove it (see README).

use anyhow::anyhow;
use async_trait::async_trait;
use aws_sdk_rekognition::{Client, error::DisplayErrorContext, primitives::Blob, types::Image};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModerationVerdict {
    Approved,
    /// Labels that triggered rejection (for logs only; never shown to users).
    Rejected(Vec<String>),
}

#[async_trait]
pub trait Moderator: Send + Sync + 'static {
    async fn check(&self, jpeg: &[u8]) -> anyhow::Result<ModerationVerdict>;
}

/// Approves everything. For local development and tests only.
pub struct NoModeration;

#[async_trait]
impl Moderator for NoModeration {
    async fn check(&self, _jpeg: &[u8]) -> anyhow::Result<ModerationVerdict> {
        Ok(ModerationVerdict::Approved)
    }
}

/// AWS Rekognition `DetectModerationLabels`: flags nudity, violence, drugs,
/// hate symbols, etc. Any label at or above `min_confidence` rejects the photo.
pub struct RekognitionModerator {
    client: Client,
    min_confidence: f32,
}

impl RekognitionModerator {
    pub fn new(client: Client, min_confidence: f32) -> Self {
        Self {
            client,
            min_confidence,
        }
    }
}

#[async_trait]
impl Moderator for RekognitionModerator {
    async fn check(&self, jpeg: &[u8]) -> anyhow::Result<ModerationVerdict> {
        let out = self
            .client
            .detect_moderation_labels()
            .image(Image::builder().bytes(Blob::new(jpeg.to_vec())).build())
            .min_confidence(self.min_confidence)
            .send()
            .await
            .map_err(|e| {
                anyhow!(
                    "rekognition DetectModerationLabels failed: {}",
                    DisplayErrorContext(e)
                )
            })?;

        let labels: Vec<String> = out
            .moderation_labels()
            .iter()
            .filter_map(|l| l.name().map(str::to_string))
            .collect();
        Ok(if labels.is_empty() {
            ModerationVerdict::Approved
        } else {
            ModerationVerdict::Rejected(labels)
        })
    }
}
