//! DynamoDB single-table implementation.
//!
//! Table: partition key `pk` (S), sort key `sk` (S), on-demand billing,
//! TTL enabled on attribute `ttl`.
//!
//! | Item          | pk               | sk                  | Notes                                   |
//! |---------------|------------------|---------------------|-----------------------------------------|
//! | User profile  | `USER#<id>`      | `PROFILE`           | email, display_name, role, password_hash |
//! | Email claim   | `EMAIL#<email>`  | `EMAIL`             | user_id — enforces unique emails         |
//! | Session       | `USER#<id>`      | `SESSION#<sid>`     | token_hash, expires_at, ttl (epoch)      |
//!
//! Every access is a single-key Get/Put/Update (or a Query within one user's
//! partition), so latency stays flat from 1 user to 100M+ and there are no
//! hot partitions or scans.

use std::{collections::HashMap, time::Duration};

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use aws_sdk_dynamodb::{
    Client,
    error::DisplayErrorContext,
    operation::{transact_write_items::TransactWriteItemsError, update_item::UpdateItemError},
    types::{AttributeValue, DeleteRequest, Put, ReturnValue, TransactWriteItem, WriteRequest},
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::{Repo, RepoError, RepoResult};
use crate::{
    config::Config,
    models::{Role, Session, User},
};

type Item = HashMap<String, AttributeValue>;

const PROFILE_SK: &str = "PROFILE";
const EMAIL_SK: &str = "EMAIL";
const SESSION_PREFIX: &str = "SESSION#";
/// DynamoDB BatchWriteItem limit.
const BATCH_LIMIT: usize = 25;

pub struct DynamoRepo {
    client: Client,
    table: String,
}

impl DynamoRepo {
    pub fn new(client: Client, table: impl Into<String>) -> Self {
        Self {
            client,
            table: table.into(),
        }
    }

    /// Build a client from the standard AWS credential chain (IRSA / Pod
    /// Identity in EKS, env vars locally) with tight timeouts and retries.
    pub async fn from_config(config: &Config) -> Self {
        let shared = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .timeout_config(
                aws_config::timeout::TimeoutConfig::builder()
                    .connect_timeout(Duration::from_secs(1))
                    .operation_attempt_timeout(Duration::from_secs(2))
                    .operation_timeout(Duration::from_secs(5))
                    .build(),
            )
            .retry_config(aws_config::retry::RetryConfig::standard().with_max_attempts(3))
            .load()
            .await;

        let mut builder = aws_sdk_dynamodb::config::Builder::from(&shared);
        if let Some(endpoint) = &config.dynamodb_endpoint {
            builder = builder.endpoint_url(endpoint);
        }
        Self::new(Client::from_conf(builder.build()), &config.dynamodb_table)
    }
}

// ---------- key + attribute helpers ----------

fn user_pk(id: Uuid) -> String {
    format!("USER#{id}")
}

fn email_pk(email: &str) -> String {
    format!("EMAIL#{email}")
}

fn session_sk(id: Uuid) -> String {
    format!("{SESSION_PREFIX}{id}")
}

fn s(v: impl Into<String>) -> AttributeValue {
    AttributeValue::S(v.into())
}

fn n(v: i64) -> AttributeValue {
    AttributeValue::N(v.to_string())
}

fn get_s<'a>(item: &'a Item, key: &str) -> anyhow::Result<&'a str> {
    item.get(key)
        .and_then(|v| v.as_s().ok())
        .map(String::as_str)
        .ok_or_else(|| anyhow!("dynamodb item missing string attribute `{key}`"))
}

fn get_uuid(item: &Item, key: &str) -> anyhow::Result<Uuid> {
    Uuid::parse_str(get_s(item, key)?).with_context(|| format!("attribute `{key}` is not a uuid"))
}

fn get_time(item: &Item, key: &str) -> anyhow::Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(get_s(item, key)?)
        .with_context(|| format!("attribute `{key}` is not RFC 3339"))?
        .with_timezone(&Utc))
}

fn sdk_err<E: std::error::Error>(op: &str, err: E) -> RepoError {
    RepoError::Other(anyhow!(
        "dynamodb {op} failed: {}",
        DisplayErrorContext(err)
    ))
}

fn user_to_item(u: &User) -> Item {
    HashMap::from([
        ("pk".to_string(), s(user_pk(u.id))),
        ("sk".to_string(), s(PROFILE_SK)),
        ("entity".to_string(), s("user")),
        ("id".to_string(), s(u.id.to_string())),
        ("email".to_string(), s(&u.email)),
        ("display_name".to_string(), s(&u.display_name)),
        ("role".to_string(), s(u.role.as_str())),
        ("password_hash".to_string(), s(&u.password_hash)),
        ("created_at".to_string(), s(u.created_at.to_rfc3339())),
        ("updated_at".to_string(), s(u.updated_at.to_rfc3339())),
    ])
}

fn item_to_user(item: &Item) -> anyhow::Result<User> {
    let role_raw = get_s(item, "role")?;
    Ok(User {
        id: get_uuid(item, "id")?,
        email: get_s(item, "email")?.to_string(),
        display_name: get_s(item, "display_name")?.to_string(),
        role: Role::parse(role_raw).ok_or_else(|| anyhow!("unknown role `{role_raw}`"))?,
        password_hash: get_s(item, "password_hash")?.to_string(),
        created_at: get_time(item, "created_at")?,
        updated_at: get_time(item, "updated_at")?,
    })
}

fn session_to_item(sess: &Session) -> Item {
    let mut item = HashMap::from([
        ("pk".to_string(), s(user_pk(sess.user_id))),
        ("sk".to_string(), s(session_sk(sess.id))),
        ("entity".to_string(), s("session")),
        ("session_id".to_string(), s(sess.id.to_string())),
        ("user_id".to_string(), s(sess.user_id.to_string())),
        ("token_hash".to_string(), s(&sess.token_hash)),
        ("created_at".to_string(), s(sess.created_at.to_rfc3339())),
        ("expires_at".to_string(), s(sess.expires_at.to_rfc3339())),
        // DynamoDB TTL deletes expired sessions for free (within ~48h of expiry).
        ("ttl".to_string(), n(sess.expires_at.timestamp())),
    ]);
    if let Some(ua) = &sess.user_agent {
        item.insert("user_agent".to_string(), s(ua));
    }
    item
}

fn item_to_session(item: &Item) -> anyhow::Result<Session> {
    Ok(Session {
        id: get_uuid(item, "session_id")?,
        user_id: get_uuid(item, "user_id")?,
        token_hash: get_s(item, "token_hash")?.to_string(),
        created_at: get_time(item, "created_at")?,
        expires_at: get_time(item, "expires_at")?,
        user_agent: get_s(item, "user_agent").ok().map(str::to_string),
    })
}

// ---------- Repo impl ----------

#[async_trait]
impl Repo for DynamoRepo {
    async fn create_user(&self, user: &User) -> RepoResult<()> {
        let email_item: Item = HashMap::from([
            ("pk".to_string(), s(email_pk(&user.email))),
            ("sk".to_string(), s(EMAIL_SK)),
            ("entity".to_string(), s("email")),
            ("user_id".to_string(), s(user.id.to_string())),
        ]);

        let email_put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(email_item))
            .condition_expression("attribute_not_exists(pk)")
            .build()
            .map_err(|e| RepoError::Other(e.into()))?;
        let user_put = Put::builder()
            .table_name(&self.table)
            .set_item(Some(user_to_item(user)))
            .condition_expression("attribute_not_exists(pk)")
            .build()
            .map_err(|e| RepoError::Other(e.into()))?;

        let result = self
            .client
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().put(email_put).build())
            .transact_items(TransactWriteItem::builder().put(user_put).build())
            .send()
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(err) => {
                let svc = err.into_service_error();
                if let TransactWriteItemsError::TransactionCanceledException(ref cancelled) = svc {
                    let condition_failed = cancelled
                        .cancellation_reasons()
                        .iter()
                        .any(|r| r.code() == Some("ConditionalCheckFailed"));
                    if condition_failed {
                        return Err(RepoError::EmailTaken);
                    }
                }
                Err(sdk_err("TransactWriteItems", svc))
            }
        }
    }

    async fn get_user(&self, id: Uuid) -> RepoResult<Option<User>> {
        let out = self
            .client
            .get_item()
            .table_name(&self.table)
            .key("pk", s(user_pk(id)))
            .key("sk", s(PROFILE_SK))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| sdk_err("GetItem", e))?;
        Ok(out.item().map(item_to_user).transpose()?)
    }

    async fn get_user_by_email(&self, email: &str) -> RepoResult<Option<User>> {
        let out = self
            .client
            .get_item()
            .table_name(&self.table)
            .key("pk", s(email_pk(email)))
            .key("sk", s(EMAIL_SK))
            .consistent_read(true)
            .projection_expression("user_id")
            .send()
            .await
            .map_err(|e| sdk_err("GetItem", e))?;
        match out.item() {
            Some(item) => self.get_user(get_uuid(item, "user_id")?).await,
            None => Ok(None),
        }
    }

    async fn update_display_name(
        &self,
        id: Uuid,
        display_name: &str,
        updated_at: DateTime<Utc>,
    ) -> RepoResult<Option<User>> {
        let result = self
            .client
            .update_item()
            .table_name(&self.table)
            .key("pk", s(user_pk(id)))
            .key("sk", s(PROFILE_SK))
            .update_expression("SET display_name = :dn, updated_at = :ua")
            .condition_expression("attribute_exists(pk)")
            .expression_attribute_values(":dn", s(display_name))
            .expression_attribute_values(":ua", s(updated_at.to_rfc3339()))
            .return_values(ReturnValue::AllNew)
            .send()
            .await;

        match result {
            Ok(out) => Ok(out.attributes().map(item_to_user).transpose()?),
            Err(err) => {
                let svc = err.into_service_error();
                if matches!(svc, UpdateItemError::ConditionalCheckFailedException(_)) {
                    Ok(None)
                } else {
                    Err(sdk_err("UpdateItem", svc))
                }
            }
        }
    }

    async fn create_session(&self, session: &Session) -> RepoResult<()> {
        self.client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(session_to_item(session)))
            .send()
            .await
            .map_err(|e| sdk_err("PutItem", e))?;
        Ok(())
    }

    async fn get_session(&self, user_id: Uuid, session_id: Uuid) -> RepoResult<Option<Session>> {
        let out = self
            .client
            .get_item()
            .table_name(&self.table)
            .key("pk", s(user_pk(user_id)))
            .key("sk", s(session_sk(session_id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| sdk_err("GetItem", e))?;
        Ok(out.item().map(item_to_session).transpose()?)
    }

    async fn rotate_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        old_hash: &str,
        new_hash: &str,
        new_expires_at: DateTime<Utc>,
    ) -> RepoResult<bool> {
        let result = self
            .client
            .update_item()
            .table_name(&self.table)
            .key("pk", s(user_pk(user_id)))
            .key("sk", s(session_sk(session_id)))
            .update_expression("SET token_hash = :new, expires_at = :exp, #ttl = :ttl")
            .condition_expression("token_hash = :old")
            .expression_attribute_names("#ttl", "ttl") // `ttl` is a reserved word
            .expression_attribute_values(":new", s(new_hash))
            .expression_attribute_values(":old", s(old_hash))
            .expression_attribute_values(":exp", s(new_expires_at.to_rfc3339()))
            .expression_attribute_values(":ttl", n(new_expires_at.timestamp()))
            .send()
            .await;

        match result {
            Ok(_) => Ok(true),
            Err(err) => {
                let svc = err.into_service_error();
                if matches!(svc, UpdateItemError::ConditionalCheckFailedException(_)) {
                    Ok(false)
                } else {
                    Err(sdk_err("UpdateItem", svc))
                }
            }
        }
    }

    async fn delete_session(&self, user_id: Uuid, session_id: Uuid) -> RepoResult<()> {
        self.client
            .delete_item()
            .table_name(&self.table)
            .key("pk", s(user_pk(user_id)))
            .key("sk", s(session_sk(session_id)))
            .send()
            .await
            .map_err(|e| sdk_err("DeleteItem", e))?;
        Ok(())
    }

    async fn delete_all_sessions(&self, user_id: Uuid) -> RepoResult<()> {
        // 1. Collect every session key in this user's partition.
        let mut keys: Vec<Item> = Vec::new();
        let mut start_key: Option<Item> = None;
        loop {
            let out = self
                .client
                .query()
                .table_name(&self.table)
                .key_condition_expression("pk = :pk AND begins_with(sk, :prefix)")
                .expression_attribute_values(":pk", s(user_pk(user_id)))
                .expression_attribute_values(":prefix", s(SESSION_PREFIX))
                .projection_expression("pk, sk")
                .consistent_read(true)
                .set_exclusive_start_key(start_key.take())
                .send()
                .await
                .map_err(|e| sdk_err("Query", e))?;
            keys.extend(out.items().iter().cloned());
            match out.last_evaluated_key() {
                Some(k) if !k.is_empty() => start_key = Some(k.clone()),
                _ => break,
            }
        }

        // 2. Delete them in batches of 25, retrying unprocessed items with backoff.
        for chunk in keys.chunks(BATCH_LIMIT) {
            let mut requests = Vec::with_capacity(chunk.len());
            for key in chunk {
                let delete = DeleteRequest::builder()
                    .set_key(Some(key.clone()))
                    .build()
                    .map_err(|e| RepoError::Other(e.into()))?;
                requests.push(WriteRequest::builder().delete_request(delete).build());
            }

            let mut pending = HashMap::from([(self.table.clone(), requests)]);
            let mut attempt: u32 = 0;
            while !pending.is_empty() {
                if attempt >= 5 {
                    return Err(RepoError::Other(anyhow!(
                        "BatchWriteItem left unprocessed items after {attempt} attempts"
                    )));
                }
                let out = self
                    .client
                    .batch_write_item()
                    .set_request_items(Some(std::mem::take(&mut pending)))
                    .send()
                    .await
                    .map_err(|e| sdk_err("BatchWriteItem", e))?;
                if let Some(unprocessed) = out.unprocessed_items() {
                    pending = unprocessed
                        .iter()
                        .filter(|(_, reqs)| !reqs.is_empty())
                        .map(|(t, reqs)| (t.clone(), reqs.clone()))
                        .collect();
                }
                if !pending.is_empty() {
                    tokio::time::sleep(Duration::from_millis(50 << attempt)).await;
                }
                attempt += 1;
            }
        }
        Ok(())
    }

    async fn ping(&self) -> RepoResult<()> {
        // A data-plane read of a key that never exists: cheap, and unlike
        // DescribeTable it isn't subject to low control-plane rate limits
        // when hundreds of pods probe at once.
        self.client
            .get_item()
            .table_name(&self.table)
            .key("pk", s("HEALTHCHECK"))
            .key("sk", s("HEALTHCHECK"))
            .send()
            .await
            .map_err(|e| sdk_err("GetItem", e))?;
        Ok(())
    }
}
