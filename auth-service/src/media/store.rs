//! Where processed photos live. S3 in production; memory for tests/local dev.

use std::{collections::HashMap, sync::Mutex};

use anyhow::anyhow;
use async_trait::async_trait;
use aws_sdk_s3::{
    Client, error::DisplayErrorContext, operation::get_object::GetObjectError,
    primitives::ByteStream,
};

/// Objects are immutable (every upload gets a new random key), so they can be
/// cached forever by browsers and CDNs.
pub const PHOTO_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";
pub const PHOTO_CONTENT_TYPE: &str = "image/jpeg";

#[async_trait]
pub trait PhotoStore: Send + Sync + 'static {
    async fn put(&self, key: &str, jpeg: Vec<u8>) -> anyhow::Result<()>;
    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>>;
    async fn delete(&self, key: &str) -> anyhow::Result<()>;
}

// ---------- S3 ----------

pub struct S3PhotoStore {
    client: Client,
    bucket: String,
}

impl S3PhotoStore {
    pub fn new(client: Client, bucket: impl Into<String>) -> Self {
        Self {
            client,
            bucket: bucket.into(),
        }
    }
}

#[async_trait]
impl PhotoStore for S3PhotoStore {
    async fn put(&self, key: &str, jpeg: Vec<u8>) -> anyhow::Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(jpeg))
            .content_type(PHOTO_CONTENT_TYPE)
            .cache_control(PHOTO_CACHE_CONTROL)
            .send()
            .await
            .map_err(|e| anyhow!("s3 PutObject failed: {}", DisplayErrorContext(e)))?;
        Ok(())
    }

    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(out) => Ok(Some(out.body.collect().await?.into_bytes().to_vec())),
            Err(err) => {
                let svc = err.into_service_error();
                if matches!(svc, GetObjectError::NoSuchKey(_)) {
                    Ok(None)
                } else {
                    Err(anyhow!("s3 GetObject failed: {}", DisplayErrorContext(svc)))
                }
            }
        }
    }

    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| anyhow!("s3 DeleteObject failed: {}", DisplayErrorContext(e)))?;
        Ok(())
    }
}

// ---------- memory ----------

/// In-process store for tests and local runs. Not shared between replicas.
#[derive(Default)]
pub struct MemoryPhotoStore {
    objects: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryPhotoStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<u8>>> {
        self.objects
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[async_trait]
impl PhotoStore for MemoryPhotoStore {
    async fn put(&self, key: &str, jpeg: Vec<u8>) -> anyhow::Result<()> {
        self.lock().insert(key.to_string(), jpeg);
        Ok(())
    }

    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self.lock().get(key).cloned())
    }

    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.lock().remove(key);
        Ok(())
    }
}
