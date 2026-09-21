use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use fs2::FileExt;
use rusqlite::{
    Connection, OptionalExtension, Row, Transaction, params, params_from_iter,
    types::Value as SqlValue,
};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;

use crate::{
    AppError, AppResult,
    models::{
        CameraMappingEntry, LoginAuditRecord, LoginUser, MotionEventRecord, PaymentFacts,
        SessionUser, TransactionRecord, UserRecord,
    },
    security::{CredentialCipher, hash_session_token, new_session_token, secure_dir, secure_file},
    thumbnail::{ThumbnailPolicy, load_policy, prepare_thumbnail, read_thumbnail, write_thumbnail},
};

pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_VIEWER: &str = "viewer";
pub const DEFAULT_ADMIN_USERNAME: &str = "admin";
pub const SESSION_TTL_SECONDS: f64 = 12.0 * 3600.0;
pub const TRANSACTION_SNAPSHOT_TTL_SECONDS: f64 = SESSION_TTL_SECONDS;
pub const MAX_TRANSACTION_SNAPSHOTS: i64 = 8;
pub const PROTECT_CONSOLE_GENERATION_SETTING: &str = "protect.console_generation";
pub const PROTECT_CONSOLE_ID_SETTING: &str = "protect.console_id";
pub const SQUARE_ACCOUNT_REVISION_SETTING: &str = "square.account_revision";
pub const ALARM_ENABLED_AFTER_SETTING: &str = "protect.alarm_enabled_after_ms";

const CURRENT_SCHEMA: &str = include_str!("../migrations/0001_current.sql");
const MIGRATION_BOOTSTRAP_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    encrypted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS camera_map (
    location_id TEXT NOT NULL,
    device_id TEXT NOT NULL DEFAULT '',
    device_name TEXT NOT NULL DEFAULT '',
    camera_id TEXT NOT NULL,
    camera_name TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (location_id, device_id)
);
CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    ts_ms INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    updated_ts_ms INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    currency TEXT NOT NULL,
    refunded_amount INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    location_id TEXT NOT NULL DEFAULT '',
    device_id TEXT NOT NULL DEFAULT '',
    device_name TEXT NOT NULL DEFAULT '',
    card_last4 TEXT NOT NULL DEFAULT '',
    receipt_url TEXT NOT NULL DEFAULT '',
    camera_id TEXT,
    thumbnail_path TEXT,
    note TEXT NOT NULL DEFAULT '',
    note_revision INTEGER NOT NULL DEFAULT 0,
    thumbnail_bytes INTEGER,
    thumbnail_policy_revision INTEGER NOT NULL DEFAULT 0,
    thumbnail_retired_at INTEGER,
    thumbnail_retired_reason TEXT NOT NULL DEFAULT '',
    raw TEXT NOT NULL DEFAULT '{}',
    alarm_state TEXT NOT NULL DEFAULT 'idle',
    alarm_claim_token TEXT,
    alarm_claimed_at REAL,
    alarm_delivered_at_ms INTEGER
);
"#;
const TRANSACTION_FILTER_SIGNATURE_PREFIX: &str = "hmac-sha256-v2:";
const TRANSACTION_FILTER_SIGNATURE_DOMAIN: &[u8] =
    b"square-unifi-protect:transaction-filter-signature:v2";
const MOTION_WEBHOOK_TOKEN_SETTING: &str = "protect.motion_webhook_token";
const MOTION_CAMERA_ID_SETTING: &str = "protect.motion_camera_id";
const MOTION_CAMERA_NAME_SETTING: &str = "protect.motion_camera_name";
const MOTION_MATCH_WINDOW_SETTING: &str = "protect.motion_match_window_seconds";
const MOTION_GRACE_SETTING: &str = "protect.motion_grace_seconds";
const MOTION_RETENTION_SETTING: &str = "protect.motion_retention_days";
const MAX_MOTION_EVENTS: i64 = 50_000;

struct ExistingPayment {
    updated_ts_ms: i64,
    ts_ms: i64,
    status: String,
    camera_id: Option<String>,
    thumbnail_path: Option<String>,
    thumbnail_retired_at: Option<i64>,
    location_id: String,
    device_id: String,
    device_name: String,
    card_last4: String,
}

#[derive(Clone)]
pub struct Store {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    data_dir: PathBuf,
    thumbnail_dir: PathBuf,
    integration_lock_path: PathBuf,
    connection: Mutex<Connection>,
    cipher: CredentialCipher,
}

pub struct IntegrationGuard {
    file: File,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SquareOAuthSnapshot {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub token_expires_at: Option<String>,
    pub environment: Option<String>,
    pub merchant_id: Option<String>,
    pub account_revision: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

impl Drop for IntegrationGuard {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

#[derive(Clone, Debug)]
pub struct MotionConfig {
    pub enabled: bool,
    pub camera_id: String,
    pub camera_name: String,
    pub match_window_seconds: i64,
    pub grace_seconds: i64,
    pub retention_days: i64,
    pub token_configured: bool,
    pub last_event_ms: Option<i64>,
}

impl MotionConfig {
    pub fn to_json(&self) -> Value {
        json!({
            "enabled": self.enabled,
            "camera_id": self.camera_id,
            "camera_name": self.camera_name,
            "match_window_seconds": self.match_window_seconds,
            "grace_seconds": self.grace_seconds,
            "retention_days": self.retention_days,
            "token_configured": self.token_configured,
            "last_event_ms": self.last_event_ms,
        })
    }
}

#[derive(Clone, Debug)]
struct MotionConfigSecret {
    public: MotionConfig,
    token: String,
}

#[derive(Clone, Debug)]
struct ThumbnailAsset {
    id: String,
    ts_ms: i64,
    path: String,
    bytes: Option<i64>,
    policy_revision: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetirementOutcome {
    Retired,
    Skipped,
    PolicyChanged,
}

impl Store {
    pub fn open(data_dir: impl AsRef<Path>) -> AppResult<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();
        fs::create_dir_all(&data_dir)?;
        secure_dir(&data_dir)?;
        let thumbnail_dir = data_dir.join("thumbnails");
        fs::create_dir_all(&thumbnail_dir)?;
        secure_dir(&thumbnail_dir)?;
        clean_interrupted_thumbnail_writes(&thumbnail_dir)?;

        let cipher = CredentialCipher::open(&data_dir)?;
        let db_path = data_dir.join("spi.db");
        let mut connection = Connection::open(&db_path)?;
        connection.busy_timeout(std::time::Duration::from_secs(10))?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON; PRAGMA secure_delete = ON; PRAGMA journal_mode = WAL;",
        )?;
        migrate_schema(&mut connection)?;
        secure_file(&db_path)?;
        for sidecar in ["spi.db-wal", "spi.db-shm"] {
            let path = data_dir.join(sidecar);
            if path.exists() {
                secure_file(&path)?;
            }
        }

        let store = Self {
            inner: Arc::new(StoreInner {
                integration_lock_path: data_dir.join(".provider-state.lock"),
                data_dir,
                thumbnail_dir,
                connection: Mutex::new(connection),
                cipher,
            }),
        };
        store.reconcile_missing_thumbnails()?;
        Ok(store)
    }

    pub fn data_dir(&self) -> &Path {
        &self.inner.data_dir
    }

    pub fn thumbnail_dir(&self) -> &Path {
        &self.inner.thumbnail_dir
    }

    fn connection(&self) -> AppResult<MutexGuard<'_, Connection>> {
        self.inner
            .connection
            .lock()
            .map_err(|_| AppError::internal(anyhow::anyhow!("database mutex poisoned")))
    }

    pub fn integration_guard(&self, exclusive: bool) -> AppResult<IntegrationGuard> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.inner.integration_lock_path)?;
        secure_file(&self.inner.integration_lock_path)?;
        if exclusive {
            FileExt::lock_exclusive(&file)?;
        } else {
            FileExt::lock_shared(&file)?;
        }
        Ok(IntegrationGuard { file })
    }

    // -- settings ---------------------------------------------------------

    pub fn get_setting(&self, key: &str) -> AppResult<Option<String>> {
        let connection = self.connection()?;
        setting_value(&connection, &self.inner.cipher, key)
    }

    pub fn get_settings<const N: usize>(
        &self,
        keys: [&str; N],
    ) -> AppResult<HashMap<String, Option<String>>> {
        let connection = self.connection()?;
        keys.into_iter()
            .map(|key| {
                Ok((
                    key.to_owned(),
                    setting_value(&connection, &self.inner.cipher, key)?,
                ))
            })
            .collect()
    }

    pub fn set_setting(&self, key: &str, value: &str, secret: bool) -> AppResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        write_setting(&transaction, &self.inner.cipher, key, value, secret)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn update_settings(
        &self,
        updates: &[(&str, &str, bool)],
        delete_keys: &[&str],
    ) -> AppResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        for (key, value, secret) in updates {
            write_setting(&transaction, &self.inner.cipher, key, value, *secret)?;
        }
        for key in delete_keys {
            transaction.execute("DELETE FROM settings WHERE key = ?", [key])?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn delete_settings(&self, keys: &[&str]) -> AppResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        for key in keys {
            transaction.execute("DELETE FROM settings WHERE key = ?", [key])?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn store_oauth_state(&self, state: &str) -> AppResult<()> {
        let state_hash = hash_session_token(state);
        let now = now_seconds();
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "DELETE FROM square_oauth_states WHERE expires_at <= ?",
            [now],
        )?;
        transaction.execute(
            "INSERT INTO square_oauth_states (state_hash, created_at, expires_at) VALUES (?, ?, ?)",
            params![state_hash, now, now + 600.0],
        )?;
        transaction.execute(
            "DELETE FROM square_oauth_states WHERE state_hash IN (SELECT state_hash \
             FROM square_oauth_states ORDER BY created_at DESC LIMIT -1 OFFSET 16)",
            [],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn consume_oauth_state(&self, state: &str) -> AppResult<bool> {
        let state_hash = hash_session_token(state);
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let now = now_seconds();
        let valid = transaction.execute(
            "DELETE FROM square_oauth_states WHERE state_hash=? AND expires_at>?",
            params![state_hash, now],
        )? == 1;
        transaction.execute(
            "DELETE FROM square_oauth_states WHERE expires_at <= ?",
            [now],
        )?;
        transaction.commit()?;
        Ok(valid)
    }

    pub fn clear_oauth_states(&self) -> AppResult<()> {
        self.connection()?
            .execute("DELETE FROM square_oauth_states", [])?;
        Ok(())
    }

    pub fn square_oauth_snapshot(&self) -> AppResult<SquareOAuthSnapshot> {
        let connection = self.connection()?;
        square_oauth_snapshot_locked(&connection, &self.inner.cipher)
    }

    pub fn update_square_oauth_tokens(
        &self,
        expected: &SquareOAuthSnapshot,
        access_token: &str,
        refresh_token: &str,
        token_expires_at: &str,
    ) -> AppResult<bool> {
        if access_token.is_empty()
            || access_token.len() > 16_384
            || refresh_token.is_empty()
            || refresh_token.len() > 16_384
            || token_expires_at.len() > 128
        {
            return Err(AppError::Upstream(
                "Square returned invalid OAuth token fields".into(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        if square_oauth_snapshot_locked(&transaction, &self.inner.cipher)? != *expected {
            transaction.commit()?;
            return Ok(false);
        }
        write_setting(
            &transaction,
            &self.inner.cipher,
            "square.access_token",
            access_token,
            true,
        )?;
        write_setting(
            &transaction,
            &self.inner.cipher,
            "square.refresh_token",
            refresh_token,
            true,
        )?;
        write_setting(
            &transaction,
            &self.inner.cipher,
            "square.token_expires_at",
            token_expires_at,
            false,
        )?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn clear_square_account_data(&self) -> AppResult<()> {
        let _guard = self.integration_guard(true)?;
        self.save_square_account_under_guard(&[], &[], true)
            .map(|_| ())
    }

    /// Save verified credentials while holding the exclusive integration guard.
    /// Account data and settings change together; the result reports whether
    /// unreferenced thumbnail files still need cleanup after the commit.
    pub fn save_square_account_under_guard(
        &self,
        updates: &[(&str, &str, bool)],
        delete_keys: &[&str],
        account_switched: bool,
    ) -> AppResult<bool> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        if account_switched {
            transaction.execute("DELETE FROM transactions", [])?;
            transaction.execute("DELETE FROM camera_map", [])?;
            transaction.execute("DELETE FROM square_poll_watermarks", [])?;
            transaction.execute("DELETE FROM square_webhook_receipts", [])?;
            transaction.execute("DELETE FROM transaction_feed_snapshots", [])?;
            transaction.execute("DELETE FROM transaction_feed_order_history", [])?;
            transaction.execute(
                "DELETE FROM settings WHERE key IN (\
                 'square.webhook_signature_key', 'square.webhook_url', \
                 'square.webhook_subscription_id') OR key LIKE 'webhook.%'",
                [],
            )?;
            write_plain_setting(
                &transaction,
                "maintenance.orphan_thumbnail_cleanup_pending",
                1,
            )?;
        }
        for (key, value, secret) in updates {
            write_setting(&transaction, &self.inner.cipher, key, value, *secret)?;
        }
        for key in delete_keys {
            transaction.execute("DELETE FROM settings WHERE key = ?", [key])?;
        }
        transaction.execute("DELETE FROM square_oauth_states", [])?;
        transaction.commit()?;
        drop(connection);

        if account_switched && let Err(error) = self.remove_orphan_thumbnails_under_guard() {
            tracing::warn!(%error, "Square account switched; thumbnail cleanup deferred");
            return Ok(true);
        }
        Ok(false)
    }

    pub fn suppress_pending_alarms(&self) -> AppResult<()> {
        self.connection()?.execute(
            "UPDATE transactions SET alarm_state='sent', alarm_claim_token=NULL, \
             alarm_claimed_at=NULL WHERE UPPER(status)='COMPLETED' AND alarm_state!='sent'",
            [],
        )?;
        Ok(())
    }

    pub fn clear_protect_evidence(&self) -> AppResult<()> {
        let _guard = self.integration_guard(true)?;
        self.clear_protect_evidence_under_guard()
    }

    pub fn clear_protect_evidence_under_guard(&self) -> AppResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT OR IGNORE INTO protect_evidence_retired (transaction_id) \
             SELECT id FROM transactions",
            [],
        )?;
        transaction.execute("DELETE FROM camera_map", [])?;
        transaction.execute("DELETE FROM thumbnail_retries", [])?;
        transaction.execute(
            "UPDATE transactions SET camera_id=NULL, thumbnail_path=NULL, thumbnail_bytes=NULL, \
             thumbnail_policy_revision=0",
            [],
        )?;
        transaction.execute(
            "UPDATE transactions SET alarm_state='sent', alarm_claim_token=NULL, \
             alarm_claimed_at=NULL WHERE UPPER(status)='COMPLETED' AND alarm_state!='sent'",
            [],
        )?;
        transaction.execute("DELETE FROM protect_motion_events", [])?;
        write_plain_setting(
            &transaction,
            "maintenance.orphan_thumbnail_cleanup_pending",
            1,
        )?;
        transaction.commit()?;
        drop(connection);
        for entry in fs::read_dir(&self.inner.thumbnail_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() && !entry.path().is_symlink() {
                fs::remove_file(entry.path())?;
            }
        }
        self.delete_settings(&["maintenance.orphan_thumbnail_cleanup_pending"])?;
        Ok(())
    }

    pub fn update_thumbnail_policy(
        &self,
        compression_enabled: bool,
        jpeg_quality: i64,
        max_dimension: i64,
        retention_days: i64,
        max_storage_mib: i64,
    ) -> AppResult<i64> {
        if !(30..=95).contains(&jpeg_quality)
            || !(320..=3840).contains(&max_dimension)
            || !(0..=3650).contains(&retention_days)
            || !(0..=1_048_576).contains(&max_storage_mib)
        {
            return Err(AppError::Unprocessable(
                "Invalid thumbnail storage policy".into(),
            ));
        }
        let _guard = self.integration_guard(true)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let mut revision = setting_value(
            &transaction,
            &self.inner.cipher,
            "thumbnail.policy_revision",
        )?
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0)
        .max(0);
        let compression_values = [
            (
                "thumbnail.compression_enabled",
                i64::from(compression_enabled).to_string(),
            ),
            ("thumbnail.jpeg_quality", jpeg_quality.to_string()),
            ("thumbnail.max_dimension", max_dimension.to_string()),
        ];
        let mut compression_changed = false;
        for (key, value) in &compression_values {
            if setting_value(&transaction, &self.inner.cipher, key)?.as_deref()
                != Some(value.as_str())
            {
                compression_changed = true;
                break;
            }
        }
        if compression_changed {
            revision = revision.saturating_add(1);
        }
        for (key, value) in [
            (
                "thumbnail.compression_enabled",
                i64::from(compression_enabled),
            ),
            ("thumbnail.jpeg_quality", jpeg_quality),
            ("thumbnail.max_dimension", max_dimension),
            ("thumbnail.retention_days", retention_days),
            ("thumbnail.max_storage_mib", max_storage_mib),
            ("thumbnail.policy_revision", revision),
        ] {
            transaction.execute(
                "INSERT INTO settings (key, value, encrypted) VALUES (?, ?, 0) \
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value, encrypted=0",
                params![key, value.to_string()],
            )?;
        }
        transaction.commit()?;
        Ok(revision)
    }

    pub fn run_thumbnail_maintenance(
        &self,
        optimize_existing: bool,
        now_ms: i64,
    ) -> AppResult<Value> {
        let policy = load_policy(self)?;
        let before = self.thumbnail_summary()?;
        let mut optimized_count = 0_i64;
        let mut optimization_error_count = 0_i64;
        let mut policy_changed = false;

        for mut asset in self.list_thumbnail_assets()? {
            if policy_changed {
                break;
            }
            if asset.bytes.is_none() {
                match regular_file_size(&self.inner.thumbnail_dir.join(&asset.path)) {
                    Ok(size) => {
                        if self.update_thumbnail_metadata(&asset, size, asset.policy_revision)? {
                            asset.bytes = Some(size);
                        }
                    }
                    Err(error) => {
                        tracing::warn!(transaction_id = %asset.id, %error, "could not account for thumbnail")
                    }
                }
            }
            if !optimize_existing
                || !policy.compression_enabled
                || asset.policy_revision >= policy.revision
            {
                continue;
            }
            let original = match read_thumbnail(&self.inner.thumbnail_dir.join(&asset.path)) {
                Ok(original) => original,
                Err(error) => {
                    optimization_error_count += 1;
                    tracing::warn!(transaction_id = %asset.id, %error, "could not read thumbnail for optimization");
                    continue;
                }
            };
            let prepared = prepare_thumbnail(&original, &policy);
            if let Some(error) = prepared.error.as_deref() {
                optimization_error_count += 1;
                tracing::warn!(transaction_id = %asset.id, %error, "could not compress thumbnail");
            }
            let _guard = self.integration_guard(true)?;
            if load_policy(self)? != policy {
                policy_changed = true;
                continue;
            }
            if !self.thumbnail_asset_is_current(&asset)? {
                continue;
            }
            if prepared.changed
                && let Err(error) =
                    write_thumbnail(&self.inner.thumbnail_dir.join(&asset.path), &prepared.data)
            {
                optimization_error_count += 1;
                tracing::warn!(transaction_id = %asset.id, %error, "could not publish optimized thumbnail");
                continue;
            }
            if self.update_thumbnail_metadata(
                &asset,
                prepared.data.len() as i64,
                prepared.policy_revision,
            )? && prepared.changed
            {
                optimized_count += 1;
            }
        }

        let assets = self.list_thumbnail_assets()?;
        let mut total_bytes = assets
            .iter()
            .map(|asset| asset.bytes.unwrap_or(0).max(0))
            .sum::<i64>();
        let mut retired_ids = HashSet::new();
        let mut retired_age_count = 0_i64;
        let mut retired_quota_count = 0_i64;

        if policy.retention_days > 0 && !policy_changed {
            let cutoff = now_ms.saturating_sub(policy.retention_days.saturating_mul(86_400_000));
            for asset in &assets {
                if asset.ts_ms >= cutoff {
                    continue;
                }
                match self.retire_thumbnail(asset, &policy, now_ms, "age")? {
                    RetirementOutcome::Retired => {
                        retired_ids.insert(asset.id.clone());
                        total_bytes = total_bytes.saturating_sub(asset.bytes.unwrap_or(0).max(0));
                        retired_age_count += 1;
                    }
                    RetirementOutcome::PolicyChanged => {
                        policy_changed = true;
                        break;
                    }
                    RetirementOutcome::Skipped => {}
                }
            }
        }

        if policy.max_storage_mib > 0 && !policy_changed {
            let quota = policy.max_storage_mib.saturating_mul(1024 * 1024);
            for asset in &assets {
                if total_bytes <= quota {
                    break;
                }
                if retired_ids.contains(&asset.id) {
                    continue;
                }
                match self.retire_thumbnail(asset, &policy, now_ms, "quota")? {
                    RetirementOutcome::Retired => {
                        total_bytes = total_bytes.saturating_sub(asset.bytes.unwrap_or(0).max(0));
                        retired_quota_count += 1;
                    }
                    RetirementOutcome::PolicyChanged => {
                        policy_changed = true;
                        break;
                    }
                    RetirementOutcome::Skipped => {}
                }
            }
        }

        if self.orphan_thumbnail_cleanup_pending()?
            && let Err(error) = self.remove_orphan_thumbnails()
        {
            tracing::warn!(%error, "could not complete thumbnail orphan cleanup");
        }
        let after = self.thumbnail_summary()?;
        let before_bytes = before["active_bytes"].as_i64().unwrap_or(0);
        let after_bytes = after["active_bytes"].as_i64().unwrap_or(0);
        Ok(json!({
            "before_bytes": before_bytes,
            "after_bytes": after_bytes,
            "bytes_saved": before_bytes.saturating_sub(after_bytes).max(0),
            "optimized_count": optimized_count,
            "optimization_error_count": optimization_error_count,
            "policy_changed_during_run": i64::from(policy_changed),
            "retired_age_count": retired_age_count,
            "retired_quota_count": retired_quota_count,
            "active_count": after["active_count"],
            "retired_count": after["retired_count"],
        }))
    }

    fn list_thumbnail_assets(&self) -> AppResult<Vec<ThumbnailAsset>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, ts_ms, thumbnail_path, thumbnail_bytes, thumbnail_policy_revision \
             FROM transactions WHERE thumbnail_path IS NOT NULL ORDER BY ts_ms, id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(ThumbnailAsset {
                id: row.get(0)?,
                ts_ms: row.get(1)?,
                path: row.get(2)?,
                bytes: row.get(3)?,
                policy_revision: row.get(4)?,
            })
        })?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    fn thumbnail_asset_is_current(&self, asset: &ThumbnailAsset) -> AppResult<bool> {
        let connection = self.connection()?;
        Ok(connection.query_row(
            "SELECT COUNT(*) FROM transactions WHERE id=? AND thumbnail_path=? \
             AND thumbnail_policy_revision=? AND thumbnail_retired_at IS NULL",
            params![asset.id, asset.path, asset.policy_revision],
            |row| row.get::<_, i64>(0),
        )? == 1)
    }

    fn update_thumbnail_metadata(
        &self,
        asset: &ThumbnailAsset,
        bytes: i64,
        policy_revision: i64,
    ) -> AppResult<bool> {
        if bytes < 0 || policy_revision < 0 {
            return Err(AppError::Unprocessable("Invalid thumbnail metadata".into()));
        }
        Ok(self.connection()?.execute(
            "UPDATE transactions SET thumbnail_bytes=?, thumbnail_policy_revision=? \
             WHERE id=? AND thumbnail_path=? AND thumbnail_retired_at IS NULL \
             AND thumbnail_policy_revision=?",
            params![
                bytes,
                policy_revision,
                asset.id,
                asset.path,
                asset.policy_revision
            ],
        )? == 1)
    }

    fn retire_thumbnail(
        &self,
        asset: &ThumbnailAsset,
        expected_policy: &ThumbnailPolicy,
        now_ms: i64,
        reason: &str,
    ) -> AppResult<RetirementOutcome> {
        if !matches!(reason, "age" | "quota") {
            return Err(AppError::BadRequest(
                "Invalid thumbnail retirement reason".into(),
            ));
        }
        let _guard = self.integration_guard(true)?;
        if &load_policy(self)? != expected_policy {
            return Ok(RetirementOutcome::PolicyChanged);
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let updated = transaction.execute(
            "UPDATE transactions SET thumbnail_path=NULL, thumbnail_bytes=NULL, \
             thumbnail_policy_revision=0, thumbnail_retired_at=?, thumbnail_retired_reason=? \
             WHERE id=? AND thumbnail_path=? AND thumbnail_retired_at IS NULL",
            params![now_ms.max(0), reason, asset.id, asset.path],
        )? == 1;
        if !updated {
            transaction.commit()?;
            return Ok(RetirementOutcome::Skipped);
        }
        transaction.execute(
            "DELETE FROM thumbnail_retries WHERE transaction_id=?",
            [&asset.id],
        )?;
        write_plain_setting(
            &transaction,
            "maintenance.orphan_thumbnail_cleanup_pending",
            1,
        )?;
        transaction.commit()?;
        drop(connection);
        self.delete_thumbnail_if_unreferenced(&asset.path)?;
        Ok(RetirementOutcome::Retired)
    }

    fn delete_thumbnail_if_unreferenced(&self, relative: &str) -> AppResult<bool> {
        if !is_local_filename(relative) {
            return Ok(false);
        }
        let referenced = self.connection()?.query_row(
            "SELECT COUNT(*) FROM transactions WHERE thumbnail_path=?",
            [relative],
            |row| row.get::<_, i64>(0),
        )? > 0;
        if referenced {
            return Ok(false);
        }
        let path = self.inner.thumbnail_dir.join(relative);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                fs::remove_file(path)?;
                Ok(true)
            }
            Ok(_) => Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub fn orphan_thumbnail_cleanup_pending(&self) -> AppResult<bool> {
        Ok(self
            .get_setting("maintenance.orphan_thumbnail_cleanup_pending")?
            .is_some())
    }

    fn remove_orphan_thumbnails(&self) -> AppResult<i64> {
        let _guard = self.integration_guard(true)?;
        self.remove_orphan_thumbnails_under_guard()
    }

    fn remove_orphan_thumbnails_under_guard(&self) -> AppResult<i64> {
        let referenced: HashSet<String> = {
            let connection = self.connection()?;
            let mut statement = connection.prepare(
                "SELECT thumbnail_path FROM transactions WHERE thumbnail_path IS NOT NULL",
            )?;
            let rows = statement.query_map([], |row| row.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        let mut removed = 0_i64;
        for entry in fs::read_dir(&self.inner.thumbnail_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry.file_type()?.is_file() && !referenced.contains(&name) {
                fs::remove_file(entry.path())?;
                removed += 1;
            }
        }
        self.delete_settings(&["maintenance.orphan_thumbnail_cleanup_pending"])?;
        Ok(removed)
    }

    // -- users and sessions ----------------------------------------------

    pub fn setup_complete(&self) -> AppResult<bool> {
        let connection = self.connection()?;
        Ok(connection
            .query_row(
                "SELECT 1 FROM users WHERE role = 'admin' AND enabled = 1 LIMIT 1",
                [],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn create_initial_admin(&self, password_hash: &str) -> AppResult<bool> {
        if password_hash.is_empty() || password_hash.len() > 1024 {
            return Err(AppError::BadRequest("Invalid password hash".into()));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let exists = transaction
            .query_row("SELECT 1 FROM users LIMIT 1", [], |_| Ok(()))
            .optional()?
            .is_some();
        if exists {
            transaction.commit()?;
            return Ok(false);
        }
        transaction.execute(
            "INSERT INTO users (username, password_hash, role, enabled, created_at) \
             VALUES ('admin', ?, 'admin', 1, ?)",
            params![password_hash, now_seconds()],
        )?;
        transaction.execute("DELETE FROM settings WHERE key = 'admin.password_hash'", [])?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        role: &str,
    ) -> AppResult<UserRecord> {
        let username = normalize_username(username)?;
        if !matches!(role, ROLE_ADMIN | ROLE_VIEWER) {
            return Err(AppError::Unprocessable("Invalid user role".into()));
        }
        let created_at = now_seconds();
        let connection = self.connection()?;
        let result = connection.execute(
            "INSERT INTO users (username, password_hash, role, enabled, created_at) \
             VALUES (?, ?, ?, 1, ?)",
            params![username, password_hash, role, created_at],
        );
        match result {
            Ok(_) => Ok(UserRecord {
                id: connection.last_insert_rowid(),
                username,
                role: role.to_owned(),
                enabled: true,
                created_at,
            }),
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(AppError::Conflict("Username already exists".into()))
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn list_users(&self) -> AppResult<Vec<UserRecord>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, username, role, enabled, created_at FROM users \
             ORDER BY username COLLATE NOCASE, id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(UserRecord {
                id: row.get(0)?,
                username: row.get(1)?,
                role: row.get(2)?,
                enabled: row.get::<_, i64>(3)? != 0,
                created_at: row.get(4)?,
            })
        })?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    pub fn reset_user_password(
        &self,
        user_id: i64,
        password_hash: &str,
    ) -> AppResult<Option<(UserRecord, i64)>> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let user = transaction
            .query_row(
                "SELECT id, username, role, enabled, created_at FROM users WHERE id = ?",
                [user_id],
                |row| {
                    Ok(UserRecord {
                        id: row.get(0)?,
                        username: row.get(1)?,
                        role: row.get(2)?,
                        enabled: row.get::<_, i64>(3)? != 0,
                        created_at: row.get(4)?,
                    })
                },
            )
            .optional()?;
        let Some(user) = user else {
            transaction.commit()?;
            return Ok(None);
        };
        transaction.execute(
            "UPDATE users SET password_hash = ?, auth_revision = auth_revision + 1 WHERE id = ?",
            params![password_hash, user_id],
        )?;
        let revoked = transaction.execute("DELETE FROM sessions WHERE user_id = ?", [user_id])?;
        transaction.commit()?;
        Ok(Some((user, revoked as i64)))
    }

    pub fn user_for_login(&self, username: &str) -> AppResult<Option<LoginUser>> {
        let Ok(username) = normalize_username(username) else {
            return Ok(None);
        };
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id, username, password_hash, role, auth_revision FROM users \
                 WHERE username = ? COLLATE NOCASE AND enabled = 1",
                [username],
                |row| {
                    Ok(LoginUser {
                        id: row.get(0)?,
                        username: row.get(1)?,
                        password_hash: row.get(2)?,
                        role: row.get(3)?,
                        auth_revision: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn create_session(
        &self,
        token: &str,
        user_id: i64,
        expected_auth_revision: i64,
        client_ip: &str,
    ) -> AppResult<SessionUser> {
        if client_ip.is_empty() || client_ip.len() > 128 {
            return Err(AppError::BadRequest("Invalid login client address".into()));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let user = transaction
            .query_row(
                "SELECT id, username, role FROM users \
                 WHERE id = ? AND enabled = 1 AND auth_revision = ?",
                params![user_id, expected_auth_revision],
                |row| {
                    Ok(SessionUser {
                        id: row.get(0)?,
                        username: row.get(1)?,
                        role: row.get(2)?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| AppError::Conflict("User is not available".into()))?;
        let now = now_seconds();
        transaction.execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            params![
                hash_session_token(token),
                user_id,
                now + SESSION_TTL_SECONDS
            ],
        )?;
        transaction.execute(
            "INSERT INTO login_audit (user_id, username, role, client_ip, logged_in_at) \
             VALUES (?, ?, ?, ?, ?)",
            params![user.id, user.username, user.role, client_ip, now],
        )?;
        transaction.commit()?;
        Ok(user)
    }

    pub fn session_user(&self, token: &str) -> AppResult<Option<SessionUser>> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let now = now_seconds();
        transaction.execute(
            "DELETE FROM sessions WHERE expires_at < ? OR NOT EXISTS (\
             SELECT 1 FROM users WHERE users.id = sessions.user_id AND users.enabled = 1)",
            [now],
        )?;
        let user = transaction
            .query_row(
                "SELECT u.id, u.username, u.role FROM sessions s \
                 JOIN users u ON u.id = s.user_id \
                 WHERE s.token_hash = ? AND s.expires_at >= ? AND u.enabled = 1",
                params![hash_session_token(token), now],
                |row| {
                    Ok(SessionUser {
                        id: row.get(0)?,
                        username: row.get(1)?,
                        role: row.get(2)?,
                    })
                },
            )
            .optional()?;
        transaction.commit()?;
        Ok(user)
    }

    pub fn delete_session(&self, token: &str) -> AppResult<()> {
        self.connection()?.execute(
            "DELETE FROM sessions WHERE token_hash = ?",
            [hash_session_token(token)],
        )?;
        Ok(())
    }

    pub fn list_login_audit(
        &self,
        limit: i64,
        before_id: Option<i64>,
    ) -> AppResult<(Vec<LoginAuditRecord>, Option<i64>)> {
        if !(1..=250).contains(&limit) || before_id.is_some_and(|value| value < 1) {
            return Err(AppError::Unprocessable(
                "Invalid login audit pagination".into(),
            ));
        }
        let connection = self.connection()?;
        let mut records = Vec::new();
        if let Some(before_id) = before_id {
            let mut statement = connection.prepare(
                "SELECT id, user_id, username, role, client_ip, logged_in_at \
                 FROM login_audit WHERE id < ? ORDER BY id DESC LIMIT ?",
            )?;
            let rows = statement.query_map(params![before_id, limit + 1], map_login_audit)?;
            records.extend(rows.collect::<Result<Vec<_>, _>>()?);
        } else {
            let mut statement = connection.prepare(
                "SELECT id, user_id, username, role, client_ip, logged_in_at \
                 FROM login_audit ORDER BY id DESC LIMIT ?",
            )?;
            let rows = statement.query_map([limit + 1], map_login_audit)?;
            records.extend(rows.collect::<Result<Vec<_>, _>>()?);
        }
        let has_more = records.len() as i64 > limit;
        records.truncate(limit as usize);
        let next = has_more.then(|| records.last().map(|row| row.id)).flatten();
        Ok((records, next))
    }

    // -- camera mappings --------------------------------------------------

    pub fn get_camera_mappings(&self) -> AppResult<Vec<CameraMappingEntry>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT location_id, device_id, device_name, camera_id, camera_name \
             FROM camera_map ORDER BY location_id, device_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(CameraMappingEntry {
                location_id: row.get(0)?,
                device_id: row.get(1)?,
                device_name: row.get(2)?,
                camera_id: row.get(3)?,
                camera_name: row.get(4)?,
            })
        })?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    pub fn replace_camera_mappings(&self, mappings: &[CameraMappingEntry]) -> AppResult<()> {
        if mappings.len() > 500 {
            return Err(AppError::Unprocessable("Too many camera mappings".into()));
        }
        let mut unique = HashSet::new();
        for mapping in mappings {
            validate_mapping(mapping)?;
            if !unique.insert((mapping.location_id.clone(), mapping.device_id.clone())) {
                return Err(AppError::Unprocessable("Duplicate camera mapping".into()));
            }
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        transaction.execute("DELETE FROM camera_map", [])?;
        for mapping in mappings {
            transaction.execute(
                "INSERT INTO camera_map \
                 (location_id, device_id, device_name, camera_id, camera_name) \
                 VALUES (?, ?, ?, ?, ?)",
                params![
                    mapping.location_id,
                    mapping.device_id,
                    mapping.device_name,
                    mapping.camera_id,
                    mapping.camera_name
                ],
            )?;
        }
        let pending = {
            let mut statement = transaction.prepare(
                "SELECT t.id, t.location_id, t.device_id, t.camera_id \
                 FROM transactions t WHERE t.thumbnail_path IS NULL \
                 AND t.thumbnail_retired_at IS NULL AND NOT EXISTS (\
                 SELECT 1 FROM protect_evidence_retired retired \
                 WHERE retired.transaction_id=t.id)",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        for (transaction_id, location_id, device_id, existing_camera) in pending {
            let mapping = camera_for_location(&transaction, &location_id, &device_id)?;
            let camera_id = mapping.map(|value| value.camera_id);
            if camera_id == existing_camera {
                continue;
            }
            transaction.execute(
                "UPDATE transactions SET camera_id=? WHERE id=?",
                params![camera_id, transaction_id],
            )?;
            if camera_id.is_some() {
                transaction.execute(
                    "INSERT INTO thumbnail_retries (transaction_id) VALUES (?) \
                     ON CONFLICT(transaction_id) DO UPDATE SET attempts=0, next_attempt_at=0, \
                     lease_token=NULL, lease_expires_at=NULL, last_error=''",
                    [&transaction_id],
                )?;
            } else {
                transaction.execute(
                    "DELETE FROM thumbnail_retries WHERE transaction_id=?",
                    [&transaction_id],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn camera_for_location(
        &self,
        location_id: &str,
        device_id: &str,
    ) -> AppResult<Option<CameraMappingEntry>> {
        let connection = self.connection()?;
        camera_for_location(&connection, location_id, device_id)
    }

    pub fn observed_devices(&self) -> AppResult<Vec<Value>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT devices.location_id, devices.device_id, \
             COALESCE((SELECT named.device_name FROM transactions named \
             WHERE named.location_id = devices.location_id \
             AND named.device_id = devices.device_id AND named.device_name != '' \
             ORDER BY named.ts_ms DESC, named.id DESC LIMIT 1), '') \
             FROM (SELECT DISTINCT location_id, device_id FROM transactions \
             WHERE device_id != '') devices \
             ORDER BY devices.location_id, 3, devices.device_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(json!({
                "location_id": row.get::<_, String>(0)?,
                "device_id": row.get::<_, String>(1)?,
                "device_name": row.get::<_, String>(2)?,
            }))
        })?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    // -- transactions -----------------------------------------------------

    pub fn upsert_payment(&self, payment: &PaymentFacts) -> AppResult<bool> {
        validate_payment(payment)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let existing = transaction
            .query_row(
                "SELECT updated_ts_ms, ts_ms, status, camera_id, thumbnail_path, \
                 thumbnail_retired_at, location_id, device_id, device_name, card_last4 \
                 FROM transactions WHERE id = ?",
                [&payment.id],
                |row| {
                    Ok(ExistingPayment {
                        updated_ts_ms: row.get(0)?,
                        ts_ms: row.get(1)?,
                        status: row.get(2)?,
                        camera_id: row.get(3)?,
                        thumbnail_path: row.get(4)?,
                        thumbnail_retired_at: row.get(5)?,
                        location_id: row.get(6)?,
                        device_id: row.get(7)?,
                        device_name: row.get(8)?,
                        card_last4: row.get(9)?,
                    })
                },
            )
            .optional()?;
        if existing
            .as_ref()
            .is_some_and(|existing| payment.updated_ts_ms < existing.updated_ts_ms)
        {
            transaction.commit()?;
            return Ok(false);
        }
        let protect_evidence_retired = transaction
            .query_row(
                "SELECT 1 FROM protect_evidence_retired WHERE transaction_id=?",
                [&payment.id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let accepted_location_id = if payment.location_id.is_empty() {
            existing
                .as_ref()
                .map(|value| value.location_id.as_str())
                .unwrap_or("")
        } else {
            &payment.location_id
        };
        let accepted_device_id = if payment.device_id.is_empty() {
            existing
                .as_ref()
                .map(|value| value.device_id.as_str())
                .unwrap_or("")
        } else {
            &payment.device_id
        };
        let source_changed = existing.as_ref().is_some_and(|value| {
            (!payment.location_id.is_empty() && payment.location_id != value.location_id)
                || (!payment.device_id.is_empty() && payment.device_id != value.device_id)
        });
        let mapping = if protect_evidence_retired {
            None
        } else {
            camera_for_location(&transaction, accepted_location_id, accepted_device_id)?
        };
        let preserve_captured_evidence = !protect_evidence_retired
            && existing.as_ref().is_some_and(|value| {
                value.thumbnail_path.is_some() && value.ts_ms == payment.ts_ms && !source_changed
            });
        let mapped_camera = if preserve_captured_evidence {
            existing
                .as_ref()
                .and_then(|value| value.camera_id.as_deref())
        } else {
            mapping.as_ref().map(|value| value.camera_id.as_str())
        };
        let evidence_changed = existing.as_ref().is_some_and(|existing| {
            existing.ts_ms != payment.ts_ms || existing.camera_id.as_deref() != mapped_camera
        });
        let storage_retired = existing
            .as_ref()
            .is_some_and(|value| value.thumbnail_retired_at.is_some());
        let retained_thumbnail = if evidence_changed || storage_retired {
            None
        } else {
            existing
                .as_ref()
                .and_then(|value| value.thumbnail_path.as_deref())
        };
        let superseded_thumbnail = evidence_changed
            .then(|| {
                existing
                    .as_ref()
                    .and_then(|value| value.thumbnail_path.clone())
            })
            .flatten();
        let new_record = existing.is_none();
        transaction.execute(
            "INSERT INTO transactions (id, created_at, ts_ms, updated_at, updated_ts_ms, \
             amount, currency, refunded_amount, status, location_id, device_id, device_name, \
             card_last4, receipt_url, camera_id, thumbnail_path, raw) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}') \
             ON CONFLICT(id) DO UPDATE SET created_at=excluded.created_at, ts_ms=excluded.ts_ms, \
             updated_at=excluded.updated_at, updated_ts_ms=excluded.updated_ts_ms, \
             amount=excluded.amount, currency=excluded.currency, \
             refunded_amount=MAX(transactions.refunded_amount, excluded.refunded_amount), \
             status=excluded.status, location_id=excluded.location_id, \
             device_id=CASE WHEN excluded.device_id='' THEN transactions.device_id ELSE excluded.device_id END, \
             device_name=CASE WHEN excluded.device_id != '' AND excluded.device_id != transactions.device_id THEN excluded.device_name \
             WHEN excluded.device_name='' THEN transactions.device_name ELSE excluded.device_name END, \
             card_last4=excluded.card_last4, receipt_url=excluded.receipt_url, \
             camera_id=excluded.camera_id, thumbnail_path=excluded.thumbnail_path, raw='{}' \
             WHERE excluded.updated_ts_ms >= transactions.updated_ts_ms",
            params![
                payment.id,
                payment.created_at,
                payment.ts_ms,
                payment.updated_at,
                payment.updated_ts_ms,
                payment.amount,
                payment.currency,
                payment.refunded_amount,
                payment.status,
                accepted_location_id,
                accepted_device_id,
                payment.device_name,
                payment.card_last4,
                payment.receipt_url,
                mapped_camera,
                retained_thumbnail,
            ],
        )?;
        if mapped_camera.is_some() && retained_thumbnail.is_none() && !storage_retired {
            if evidence_changed {
                transaction.execute(
                    "INSERT INTO thumbnail_retries (transaction_id) VALUES (?) \
                     ON CONFLICT(transaction_id) DO UPDATE SET attempts=0, next_attempt_at=0, \
                     lease_token=NULL, lease_expires_at=NULL, last_error=''",
                    [&payment.id],
                )?;
            } else {
                transaction.execute(
                    "INSERT OR IGNORE INTO thumbnail_retries (transaction_id) VALUES (?)",
                    [&payment.id],
                )?;
            }
        } else {
            transaction.execute(
                "DELETE FROM thumbnail_retries WHERE transaction_id = ?",
                [&payment.id],
            )?;
        }
        let timestamp_changed = existing
            .as_ref()
            .is_some_and(|value| value.ts_ms != payment.ts_ms);
        if new_record || timestamp_changed {
            transaction.execute(
                "UPDATE transaction_feed_state SET order_revision = order_revision + 1 WHERE singleton = 1",
                [],
            )?;
        }
        if timestamp_changed {
            transaction.execute("DELETE FROM transaction_feed_snapshots", [])?;
        }
        if let Some(existing) = existing.as_ref() {
            let accepted_device_name =
                if !payment.device_id.is_empty() && payment.device_id != existing.device_id {
                    payment.device_name.as_str()
                } else if payment.device_name.is_empty() {
                    existing.device_name.as_str()
                } else {
                    payment.device_name.as_str()
                };
            if existing.status != payment.status
                || existing.location_id != accepted_location_id
                || existing.device_id != accepted_device_id
                || existing.device_name != accepted_device_name
                || existing.card_last4 != payment.card_last4
            {
                transaction.execute(
                    "DELETE FROM transaction_feed_snapshots WHERE filter_signature != ''",
                    [],
                )?;
            }
        }
        suppress_historical_alarm(&transaction, payment, existing.as_ref())?;
        if superseded_thumbnail.is_some() {
            write_plain_setting(
                &transaction,
                "maintenance.orphan_thumbnail_cleanup_pending",
                1,
            )?;
        }
        transaction.commit()?;
        drop(connection);
        if let Some(path) = superseded_thumbnail
            && let Err(error) = self.delete_thumbnail_if_unreferenced(&path)
        {
            tracing::warn!(thumbnail_path = %path, %error, "could not delete superseded thumbnail");
        }
        Ok(new_record)
    }

    pub fn get_transaction(&self, id: &str) -> AppResult<Option<TransactionRecord>> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT t.*, COALESCE(r.attempts, 0) thumbnail_retry_attempts \
                 FROM transactions t LEFT JOIN thumbnail_retries r ON r.transaction_id=t.id \
                 WHERE t.id = ?",
                [id],
                map_transaction,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn square_poll_watermark(&self, location_id: &str) -> AppResult<Option<i64>> {
        self.connection()?
            .query_row(
                "SELECT polled_through_ms FROM square_poll_watermarks WHERE location_id=?",
                [location_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn advance_square_poll_watermark(
        &self,
        location_id: &str,
        boundary_ms: i64,
    ) -> AppResult<()> {
        if boundary_ms < 0 {
            return Err(AppError::Unprocessable(
                "Square poll watermark cannot be negative".into(),
            ));
        }
        self.connection()?.execute(
            "INSERT INTO square_poll_watermarks (location_id, polled_through_ms) VALUES (?, ?) \
             ON CONFLICT(location_id) DO UPDATE SET polled_through_ms=\
             MAX(square_poll_watermarks.polled_through_ms, excluded.polled_through_ms)",
            params![location_id, boundary_ms],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub fn attach_thumbnail(
        &self,
        transaction_id: &str,
        camera_id: &str,
        ts_ms: i64,
        filename: &str,
        bytes: i64,
        policy_revision: i64,
    ) -> AppResult<bool> {
        if !is_local_filename(filename) || bytes < 0 || policy_revision < 0 {
            return Err(AppError::Unprocessable("Invalid thumbnail metadata".into()));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let changed = transaction.execute(
            "UPDATE transactions SET thumbnail_path=?, thumbnail_bytes=?, \
             thumbnail_policy_revision=?, thumbnail_retired_at=NULL, \
             thumbnail_retired_reason='' WHERE id=? AND camera_id=? AND ts_ms=?",
            params![
                filename,
                bytes,
                policy_revision,
                transaction_id,
                camera_id,
                ts_ms
            ],
        )? == 1;
        if changed {
            transaction.execute(
                "DELETE FROM thumbnail_retries WHERE transaction_id=?",
                [transaction_id],
            )?;
        }
        transaction.commit()?;
        Ok(changed)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn complete_thumbnail_retry(
        &self,
        transaction_id: &str,
        lease_token: &str,
        camera_id: &str,
        ts_ms: i64,
        filename: &str,
        bytes: i64,
        policy_revision: i64,
    ) -> AppResult<bool> {
        if !is_local_filename(filename) || bytes < 0 || policy_revision < 0 {
            return Err(AppError::Unprocessable("Invalid thumbnail metadata".into()));
        }
        validate_camera_id(camera_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let claimed = transaction
            .query_row(
                "SELECT 1 FROM thumbnail_retries WHERE transaction_id=? AND lease_token=?",
                params![transaction_id, lease_token],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !claimed {
            transaction.commit()?;
            return Ok(false);
        }
        let changed = transaction.execute(
            "UPDATE transactions SET thumbnail_path=?, thumbnail_bytes=?, \
             thumbnail_policy_revision=? WHERE id=? AND camera_id=? AND ts_ms=? \
             AND thumbnail_path IS NULL AND thumbnail_retired_at IS NULL",
            params![
                filename,
                bytes,
                policy_revision,
                transaction_id,
                camera_id,
                ts_ms
            ],
        )? == 1;
        if changed {
            transaction.execute(
                "DELETE FROM thumbnail_retries WHERE transaction_id=? AND lease_token=?",
                params![transaction_id, lease_token],
            )?;
        } else {
            requeue_changed_thumbnail_locked(&transaction, transaction_id, lease_token)?;
        }
        transaction.commit()?;
        Ok(changed)
    }

    pub fn requeue_missing_thumbnail(
        &self,
        transaction_id: &str,
        expected_path: &str,
    ) -> AppResult<bool> {
        if !is_local_filename(expected_path) {
            return Ok(false);
        }
        let path = self.inner.thumbnail_dir.join(expected_path);
        if fs::symlink_metadata(&path)
            .ok()
            .is_some_and(|metadata| metadata.file_type().is_file())
        {
            return Ok(false);
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let updated = transaction.execute(
            "UPDATE transactions SET thumbnail_path=NULL, thumbnail_bytes=NULL, \
             thumbnail_policy_revision=0 WHERE id=? AND thumbnail_path=? \
             AND thumbnail_retired_at IS NULL",
            params![transaction_id, expected_path],
        )? == 1;
        if !updated {
            transaction.commit()?;
            return Ok(false);
        }
        let coordinates = transaction
            .query_row(
                "SELECT location_id, device_id FROM transactions WHERE id=?",
                [transaction_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let retired = transaction
            .query_row(
                "SELECT 1 FROM protect_evidence_retired WHERE transaction_id=?",
                [transaction_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let mapping = if retired {
            None
        } else if let Some((location_id, device_id)) = coordinates {
            camera_for_location(&transaction, &location_id, &device_id)?
        } else {
            None
        };
        let camera_id = mapping.as_ref().map(|mapping| mapping.camera_id.as_str());
        transaction.execute(
            "UPDATE transactions SET camera_id=? WHERE id=?",
            params![camera_id, transaction_id],
        )?;
        if camera_id.is_some() {
            transaction.execute(
                "INSERT INTO thumbnail_retries (transaction_id) VALUES (?) \
                 ON CONFLICT(transaction_id) DO UPDATE SET attempts=0, next_attempt_at=0, \
                 lease_token=NULL, lease_expires_at=NULL, last_error=''",
                [transaction_id],
            )?;
        } else {
            transaction.execute(
                "DELETE FROM thumbnail_retries WHERE transaction_id=?",
                [transaction_id],
            )?;
        }
        transaction.commit()?;
        Ok(true)
    }

    pub fn claim_due_thumbnail_retries(
        &self,
        limit: i64,
        now: f64,
    ) -> AppResult<Vec<(TransactionRecord, String)>> {
        let lease_token = new_session_token();
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "UPDATE thumbnail_retries SET lease_token=?, lease_expires_at=? \
             WHERE transaction_id IN (SELECT r.transaction_id FROM thumbnail_retries r \
             JOIN transactions t ON t.id=r.transaction_id \
             WHERE r.next_attempt_at <= ? AND (r.lease_expires_at IS NULL OR r.lease_expires_at <= ?) \
             AND t.camera_id IS NOT NULL AND t.thumbnail_path IS NULL \
             AND t.thumbnail_retired_at IS NULL ORDER BY r.next_attempt_at, t.ts_ms LIMIT ?)",
            params![lease_token, now + 60.0, now, now, limit.clamp(1, 100)],
        )?;
        let records = {
            let mut statement = transaction.prepare(
                "SELECT t.*, r.attempts thumbnail_retry_attempts FROM thumbnail_retries r \
                 JOIN transactions t ON t.id=r.transaction_id WHERE r.lease_token=? \
                 ORDER BY r.next_attempt_at, t.ts_ms",
            )?;
            let rows = statement.query_map([&lease_token], map_transaction)?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        transaction.commit()?;
        Ok(records
            .into_iter()
            .map(|record| (record, lease_token.clone()))
            .collect())
    }

    pub fn fail_thumbnail_retry(
        &self,
        transaction_id: &str,
        lease_token: &str,
        camera_id: &str,
        ts_ms: i64,
        error: &str,
        now: f64,
    ) -> AppResult<bool> {
        let bounded_error: String = error.chars().take(1000).collect();
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let attempts = transaction
            .query_row(
                "SELECT attempts FROM thumbnail_retries WHERE transaction_id=? AND lease_token=?",
                params![transaction_id, lease_token],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let Some(attempts) = attempts else {
            transaction.commit()?;
            return Ok(false);
        };
        let same_evidence = transaction
            .query_row(
                "SELECT camera_id, ts_ms, thumbnail_path, thumbnail_retired_at \
                 FROM transactions WHERE id=?",
                [transaction_id],
                |row| {
                    Ok(
                        row.get::<_, Option<String>>(0)?.as_deref() == Some(camera_id)
                            && row.get::<_, i64>(1)? == ts_ms
                            && row.get::<_, Option<String>>(2)?.is_none()
                            && row.get::<_, Option<i64>>(3)?.is_none(),
                    )
                },
            )
            .optional()?
            .unwrap_or(false);
        if !same_evidence {
            requeue_changed_thumbnail_locked(&transaction, transaction_id, lease_token)?;
            transaction.commit()?;
            return Ok(true);
        }
        let next_attempt = attempts.saturating_add(1);
        let delay = 30_i64
            .saturating_mul(1_i64 << attempts.clamp(0, 30))
            .min(3600) as f64;
        let changed = transaction.execute(
            "UPDATE thumbnail_retries SET attempts=?, next_attempt_at=?, \
             lease_token=NULL, lease_expires_at=NULL, last_error=? \
             WHERE transaction_id=? AND lease_token=?",
            params![
                next_attempt,
                now + delay,
                bounded_error,
                transaction_id,
                lease_token
            ],
        )? == 1;
        transaction.commit()?;
        Ok(changed)
    }

    pub fn pending_alarm_ids(&self, limit: i64) -> AppResult<Vec<String>> {
        let connection = self.connection()?;
        connection.execute(
            "UPDATE transactions SET alarm_state='idle', alarm_claim_token=NULL, alarm_claimed_at=NULL \
             WHERE alarm_state='in_progress' AND (alarm_claimed_at IS NULL OR alarm_claimed_at <= ?)",
            [now_seconds() - 60.0],
        )?;
        let mut statement = connection.prepare(
            "SELECT id FROM transactions WHERE UPPER(status)='COMPLETED' AND alarm_state='idle' \
             ORDER BY ts_ms ASC LIMIT ?",
        )?;
        let rows = statement.query_map([limit.clamp(1, 500)], |row| row.get(0))?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    pub fn claim_alarm_trigger(&self, transaction_id: &str) -> AppResult<Option<String>> {
        let token = new_session_token();
        let connection = self.connection()?;
        connection.execute(
            "UPDATE transactions SET alarm_state='idle', alarm_claim_token=NULL, alarm_claimed_at=NULL \
             WHERE alarm_state='in_progress' AND (alarm_claimed_at IS NULL OR alarm_claimed_at <= ?)",
            [now_seconds() - 60.0],
        )?;
        let claimed = connection.execute(
            "UPDATE transactions SET alarm_state='in_progress', alarm_claim_token=?, alarm_claimed_at=? \
             WHERE id=? AND UPPER(status)='COMPLETED' AND alarm_state='idle'",
            params![token, now_seconds(), transaction_id],
        )? == 1;
        Ok(claimed.then_some(token))
    }

    pub fn mark_alarm_sent(
        &self,
        transaction_id: &str,
        claim_token: &str,
        delivered_at_ms: i64,
    ) -> AppResult<bool> {
        Ok(self.connection()?.execute(
            "UPDATE transactions SET alarm_state='sent', alarm_claim_token=NULL, \
             alarm_claimed_at=NULL, alarm_delivered_at_ms=? WHERE id=? \
             AND alarm_state='in_progress' AND alarm_claim_token=?",
            params![delivered_at_ms.max(0), transaction_id, claim_token],
        )? == 1)
    }

    pub fn release_alarm_claim(&self, transaction_id: &str, claim_token: &str) -> AppResult<bool> {
        Ok(self.connection()?.execute(
            "UPDATE transactions SET alarm_state='idle', alarm_claim_token=NULL, alarm_claimed_at=NULL \
             WHERE id=? AND alarm_state='in_progress' AND alarm_claim_token=?",
            params![transaction_id, claim_token],
        )? == 1)
    }

    pub fn list_transactions_page(
        &self,
        limit: i64,
        offset: i64,
        snapshot_id: Option<i64>,
        query: &str,
        status: &str,
    ) -> AppResult<(Vec<TransactionRecord>, i64)> {
        if !(1..=500).contains(&limit) || !(0..=1_000_000).contains(&offset) {
            return Err(AppError::Unprocessable(
                "Invalid transaction pagination".into(),
            ));
        }
        let (signature, filter_sql, filter_values) =
            transaction_filter(query, status, &self.inner.cipher)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let now = now_seconds();
        transaction.execute(
            "DELETE FROM transaction_feed_snapshots WHERE last_accessed_at < ?",
            [now - TRANSACTION_SNAPSHOT_TTL_SECONDS],
        )?;
        let snapshot = if let Some(id) = snapshot_id {
            let row = transaction
                .query_row(
                    "SELECT id, rowid_boundary, filter_signature FROM transaction_feed_snapshots \
                     WHERE id = ?",
                    [id],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()?;
            let Some((id, boundary, stored_signature)) = row else {
                return Err(AppError::Conflict(
                    "Transaction page snapshot expired".into(),
                ));
            };
            if stored_signature != signature {
                return Err(AppError::Conflict(
                    "Transaction page snapshot belongs to different filters".into(),
                ));
            }
            transaction.execute(
                "UPDATE transaction_feed_snapshots SET last_accessed_at=? WHERE id=?",
                params![now, id],
            )?;
            (id, boundary)
        } else {
            let revision: i64 = transaction.query_row(
                "SELECT order_revision FROM transaction_feed_state WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            let boundary: i64 = transaction.query_row(
                "SELECT COALESCE(MAX(rowid), 0) FROM transactions",
                [],
                |row| row.get(0),
            )?;
            transaction.execute(
                "INSERT INTO transaction_feed_snapshots \
                 (order_revision, rowid_boundary, filter_signature, created_at, last_accessed_at) \
                 VALUES (?, ?, ?, ?, ?) ON CONFLICT(order_revision, rowid_boundary, filter_signature) \
                 DO UPDATE SET last_accessed_at=excluded.last_accessed_at",
                params![revision, boundary, signature, now, now],
            )?;
            let id: i64 = transaction.query_row(
                "SELECT id FROM transaction_feed_snapshots WHERE order_revision=? \
                 AND rowid_boundary=? AND filter_signature=?",
                params![revision, boundary, signature],
                |row| row.get(0),
            )?;
            (id, boundary)
        };

        transaction.execute(
            "DELETE FROM transaction_feed_snapshots WHERE id IN (\
             SELECT id FROM transaction_feed_snapshots WHERE id != ? \
             ORDER BY last_accessed_at DESC, id DESC LIMIT -1 OFFSET ?)",
            params![snapshot.0, MAX_TRANSACTION_SNAPSHOTS - 1],
        )?;

        let sql = format!(
            "SELECT t.*, COALESCE(r.attempts, 0) thumbnail_retry_attempts \
             FROM transactions t LEFT JOIN thumbnail_retries r ON r.transaction_id=t.id \
             WHERE t.rowid <= ? {filter_sql} ORDER BY t.ts_ms DESC, t.id DESC LIMIT ? OFFSET ?"
        );
        let mut values = vec![SqlValue::Integer(snapshot.1)];
        values.extend(filter_values);
        values.push(SqlValue::Integer(limit));
        values.push(SqlValue::Integer(offset));
        let rows = {
            let mut statement = transaction.prepare(&sql)?;
            let mapped = statement.query_map(params_from_iter(values), map_transaction)?;
            mapped.collect::<Result<Vec<_>, _>>()?
        };
        transaction.commit()?;
        Ok((rows, snapshot.0))
    }

    pub fn set_transaction_note(
        &self,
        id: &str,
        note: &str,
        expected_revision: i64,
    ) -> AppResult<Option<(String, i64)>> {
        validate_note(note)?;
        if expected_revision < 0 {
            return Err(AppError::Unprocessable(
                "Invalid transaction note revision".into(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let current = transaction
            .query_row(
                "SELECT note, note_revision FROM transactions WHERE id = ?",
                [id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        let Some((current_note, revision)) = current else {
            transaction.commit()?;
            return Ok(None);
        };
        if revision != expected_revision {
            return Err(AppError::Conflict(
                "Transaction note changed while it was being edited".into(),
            ));
        }
        if current_note == note {
            transaction.commit()?;
            return Ok(Some((current_note, revision)));
        }
        let revision = revision + 1;
        transaction.execute(
            "UPDATE transactions SET note=?, note_revision=? WHERE id=?",
            params![note, revision, id],
        )?;
        transaction.execute(
            "DELETE FROM transaction_feed_snapshots WHERE filter_signature != ''",
            [],
        )?;
        transaction.commit()?;
        Ok(Some((note.to_owned(), revision)))
    }

    pub fn transaction_export_facts(&self) -> AppResult<Vec<TransactionRecord>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT t.*, 0 thumbnail_retry_attempts FROM transactions t \
             ORDER BY t.ts_ms DESC, t.id DESC",
        )?;
        let rows = statement.query_map([], map_transaction)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    pub fn thumbnail_summary(&self) -> AppResult<Value> {
        let connection = self.connection()?;
        let (count, bytes): (i64, i64) = connection.query_row(
            "SELECT COUNT(*), COALESCE(SUM(COALESCE(thumbnail_bytes, 0)), 0) \
             FROM transactions WHERE thumbnail_path IS NOT NULL",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let retired: i64 = connection.query_row(
            "SELECT COUNT(*) FROM transactions WHERE thumbnail_retired_at IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        Ok(json!({
            "active_count": count,
            "active_bytes": bytes,
            "retired_count": retired,
        }))
    }

    pub fn queue_depths(&self) -> AppResult<Value> {
        let connection = self.connection()?;
        connection.execute(
            "UPDATE transactions SET alarm_state='idle', alarm_claim_token=NULL, alarm_claimed_at=NULL \
             WHERE alarm_state='in_progress' AND (alarm_claimed_at IS NULL OR alarm_claimed_at <= ?)",
            [now_seconds() - 60.0],
        )?;
        let thumbnails: i64 =
            connection.query_row("SELECT COUNT(*) FROM thumbnail_retries", [], |row| {
                row.get(0)
            })?;
        let alarms: i64 = connection.query_row(
            "SELECT COUNT(*) FROM transactions WHERE UPPER(status)='COMPLETED' AND alarm_state='idle'",
            [],
            |row| row.get(0),
        )?;
        Ok(json!({
            "thumbnails_pending": thumbnails,
            "alarms_pending": alarms,
        }))
    }

    pub fn alarm_summary(&self) -> AppResult<Value> {
        let connection = self.connection()?;
        connection.execute(
            "UPDATE transactions SET alarm_state='idle', alarm_claim_token=NULL, alarm_claimed_at=NULL \
             WHERE alarm_state='in_progress' AND (alarm_claimed_at IS NULL OR alarm_claimed_at <= ?)",
            [now_seconds() - 60.0],
        )?;
        let row = connection.query_row(
            "SELECT \
             SUM(CASE WHEN UPPER(status)='COMPLETED' AND alarm_state='idle' THEN 1 ELSE 0 END), \
             SUM(CASE WHEN UPPER(status)='COMPLETED' AND alarm_state='in_progress' THEN 1 ELSE 0 END), \
             SUM(CASE WHEN alarm_delivered_at_ms IS NOT NULL THEN 1 ELSE 0 END), \
             MAX(alarm_delivered_at_ms) FROM transactions",
            [],
            |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(3)?,
                ))
            },
        )?;
        let trigger = setting_value(&connection, &self.inner.cipher, "protect.alarm_trigger_id")?;
        Ok(json!({
            "configured": trigger.as_ref().is_some_and(|value| !value.is_empty()),
            "trigger_id": trigger.unwrap_or_default(),
            "pending": row.0,
            "in_progress": row.1,
            "delivered": row.2,
            "last_delivered_at_ms": row.3,
        }))
    }

    // -- Square webhook metrics ------------------------------------------

    pub fn square_webhook_config(&self) -> AppResult<(String, String, String)> {
        Ok((
            self.get_setting("square.webhook_signature_key")?
                .unwrap_or_default(),
            self.get_setting("square.webhook_url")?.unwrap_or_default(),
            self.get_setting("square.merchant_id")?.unwrap_or_default(),
        ))
    }

    pub fn webhook_receipt_exists(&self, key: &str) -> AppResult<bool> {
        let connection = self.connection()?;
        Ok(connection
            .query_row(
                "SELECT 1 FROM square_webhook_receipts WHERE event_key=?",
                [key],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn record_webhook_delivery(&self, received_at_ms: i64) -> AppResult<()> {
        if received_at_ms < 0 {
            return Err(AppError::Unprocessable(
                "Invalid webhook delivery time".into(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        increment_plain_setting(&transaction, "webhook.delivery_count")?;
        max_plain_setting(&transaction, "webhook.last_event_ms", received_at_ms)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn record_webhook_receipt(
        &self,
        key: &str,
        event_type: &str,
        received_at_ms: i64,
        event_created_at_ms: Option<i64>,
    ) -> AppResult<bool> {
        if key.len() != 64
            || !key
                .bytes()
                .all(|value| value.is_ascii_hexdigit() && !value.is_ascii_uppercase())
            || !matches!(event_type, "payment.created" | "payment.updated")
            || received_at_ms < 0
            || event_created_at_ms.is_some_and(|value| value < 0)
        {
            return Err(AppError::Unprocessable(
                "Invalid Square webhook receipt".into(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let previous_last_payment =
            setting_value(&transaction, &self.inner.cipher, "webhook.last_payment_ms")?
                .and_then(|value| value.parse::<i64>().ok());
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO square_webhook_receipts \
             (event_key, event_type, received_at_ms, event_created_at_ms) VALUES (?, ?, ?, ?)",
            params![key, event_type, received_at_ms, event_created_at_ms],
        )? == 1;
        if inserted {
            increment_plain_setting(&transaction, "webhook.accepted_payment_count")?;
            if previous_last_payment.is_none_or(|previous| received_at_ms >= previous) {
                write_plain_setting(&transaction, "webhook.last_payment_ms", received_at_ms)?;
                if let Some(created) = event_created_at_ms {
                    write_plain_setting(
                        &transaction,
                        "webhook.last_delivery_lag_ms",
                        received_at_ms - created,
                    )?;
                } else {
                    transaction.execute(
                        "DELETE FROM settings WHERE key='webhook.last_delivery_lag_ms'",
                        [],
                    )?;
                }
            }
        } else {
            increment_plain_setting(&transaction, "webhook.duplicate_count")?;
        }
        transaction.execute(
            "DELETE FROM square_webhook_receipts WHERE event_key IN (\
             SELECT event_key FROM square_webhook_receipts \
             ORDER BY received_at_ms DESC LIMIT -1 OFFSET 4096)",
            [],
        )?;
        transaction.commit()?;
        Ok(inserted)
    }

    pub fn webhook_metrics(&self) -> AppResult<Value> {
        let connection = self.connection()?;
        let configured = setting_value(
            &connection,
            &self.inner.cipher,
            "square.webhook_signature_key",
        )?
        .is_some_and(|value| !value.is_empty())
            && setting_value(&connection, &self.inner.cipher, "square.webhook_url")?
                .is_some_and(|value| !value.is_empty());
        let read = |key: &str| -> AppResult<Option<i64>> {
            Ok(setting_value(&connection, &self.inner.cipher, key)?
                .and_then(|value| value.parse().ok()))
        };
        Ok(json!({
            "configured": configured,
            "last_event_ms": read("webhook.last_event_ms")?,
            "delivery_count": read("webhook.delivery_count")?.unwrap_or(0),
            "last_payment_ms": read("webhook.last_payment_ms")?,
            "last_delivery_lag_ms": read("webhook.last_delivery_lag_ms")?,
            "accepted_payment_count": read("webhook.accepted_payment_count")?.unwrap_or(0),
            "duplicate_count": read("webhook.duplicate_count")?.unwrap_or(0),
        }))
    }

    // -- Protect motion webhooks -----------------------------------------

    pub fn motion_config(&self) -> AppResult<MotionConfig> {
        let connection = self.connection()?;
        let mut config = motion_config_locked(&connection, &self.inner.cipher)?;
        config.public.last_event_ms = if config.public.camera_id.is_empty() {
            None
        } else {
            connection.query_row(
                "SELECT MAX(received_at_ms) FROM protect_motion_events WHERE camera_id=?",
                [&config.public.camera_id],
                |row| row.get(0),
            )?
        };
        Ok(config.public)
    }

    pub fn configure_motion(
        &self,
        camera_id: &str,
        camera_name: &str,
        match_window_seconds: i64,
        grace_seconds: i64,
        retention_days: i64,
        rotate_token: bool,
    ) -> AppResult<(MotionConfig, Option<String>)> {
        validate_camera_id(camera_id)?;
        if camera_name.len() > 128 || has_forbidden_controls(camera_name, false) {
            return Err(AppError::Unprocessable(
                "Invalid Protect motion camera name".into(),
            ));
        }
        if !(1..=300).contains(&match_window_seconds) {
            return Err(AppError::Unprocessable(
                "Motion match window must be 1 to 300 seconds".into(),
            ));
        }
        if !(0..=600).contains(&grace_seconds) {
            return Err(AppError::Unprocessable(
                "Motion grace period must be 0 to 600 seconds".into(),
            ));
        }
        if !(1..=365).contains(&retention_days) {
            return Err(AppError::Unprocessable(
                "Motion retention must be 1 to 365 days".into(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let current = motion_config_locked(&transaction, &self.inner.cipher)?;
        let (token, revealed) =
            if rotate_token || current.token.is_empty() || current.public.camera_id != camera_id {
                let token = new_session_token();
                (token.clone(), Some(token))
            } else {
                (current.token, None)
            };
        for (key, value, secret) in [
            (MOTION_WEBHOOK_TOKEN_SETTING, token.as_str(), true),
            (MOTION_CAMERA_ID_SETTING, camera_id, false),
            (MOTION_CAMERA_NAME_SETTING, camera_name, false),
            (
                MOTION_MATCH_WINDOW_SETTING,
                &match_window_seconds.to_string(),
                false,
            ),
            (MOTION_GRACE_SETTING, &grace_seconds.to_string(), false),
            (MOTION_RETENTION_SETTING, &retention_days.to_string(), false),
        ] {
            write_setting(&transaction, &self.inner.cipher, key, value, secret)?;
        }
        transaction.commit()?;
        drop(connection);
        Ok((self.motion_config()?, revealed))
    }

    pub fn disable_motion(&self) -> AppResult<()> {
        self.delete_settings(&[
            MOTION_WEBHOOK_TOKEN_SETTING,
            MOTION_CAMERA_ID_SETTING,
            MOTION_CAMERA_NAME_SETTING,
            MOTION_MATCH_WINDOW_SETTING,
            MOTION_GRACE_SETTING,
            MOTION_RETENTION_SETTING,
        ])
    }

    pub fn authenticate_motion(&self, token: &str) -> AppResult<MotionConfig> {
        if token.len() > 512 {
            return Err(AppError::Unauthorized(
                "Invalid Protect motion webhook token".into(),
            ));
        }
        let connection = self.connection()?;
        let config = motion_config_locked(&connection, &self.inner.cipher)?;
        if !config.public.enabled || !constant_time_text_equal(token, &config.token) {
            return Err(AppError::Unauthorized(
                "Invalid Protect motion webhook token".into(),
            ));
        }
        Ok(config.public)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_motion(
        &self,
        token: &str,
        event_key: &str,
        event_ts_ms: i64,
        received_at_ms: i64,
        delivery_method: &str,
        alarm_name: &str,
        device_identifiers: &[String],
    ) -> AppResult<bool> {
        if !(1..=80).contains(&event_key.len())
            || !matches!(delivery_method, "get" | "post")
            || event_ts_ms < 0
            || received_at_ms < 0
            || alarm_name.len() > 256
            || has_forbidden_controls(alarm_name, false)
        {
            return Err(AppError::Unprocessable(
                "Invalid Protect motion event".into(),
            ));
        }
        let mut normalized_devices = Vec::new();
        for value in device_identifiers {
            let value = value.trim();
            if value.is_empty() || normalized_devices.iter().any(|existing| existing == value) {
                continue;
            }
            if value.len() > 128 || has_forbidden_controls(value, false) {
                return Err(AppError::Unprocessable(
                    "Invalid Protect motion device identifier".into(),
                ));
            }
            normalized_devices.push(value.to_owned());
        }
        if normalized_devices.len() > 64 {
            return Err(AppError::Unprocessable(
                "Too many Protect motion device identifiers".into(),
            ));
        }
        let device_identifiers_json =
            serde_json::to_string(&normalized_devices).map_err(AppError::internal)?;
        if device_identifiers_json.len() > 4096 {
            return Err(AppError::Unprocessable(
                "Protect motion device identifiers are too large".into(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let config = motion_config_locked(&transaction, &self.inner.cipher)?;
        if !config.public.enabled || !constant_time_text_equal(token, &config.token) {
            return Err(AppError::Unauthorized(
                "Invalid Protect motion webhook token".into(),
            ));
        }
        let retention_ms = config.public.retention_days * 86_400_000;
        if event_ts_ms < received_at_ms - retention_ms {
            return Err(AppError::Unprocessable(
                "Protect motion timestamp is too old".into(),
            ));
        }
        transaction.execute(
            "DELETE FROM protect_motion_events WHERE expires_at_ms <= ?",
            [received_at_ms],
        )?;
        let created = transaction.execute(
            "INSERT OR IGNORE INTO protect_motion_events \
             (event_key, camera_id, camera_name, event_ts_ms, received_at_ms, \
             evaluate_after_ms, expires_at_ms, match_window_ms, delivery_method, \
             alarm_name, device_identifiers) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                event_key,
                config.public.camera_id,
                config.public.camera_name,
                event_ts_ms,
                received_at_ms,
                received_at_ms.max(event_ts_ms) + config.public.grace_seconds * 1000,
                event_ts_ms + retention_ms,
                config.public.match_window_seconds * 1000,
                delivery_method,
                alarm_name,
                device_identifiers_json,
            ],
        )? == 1;
        transaction.execute(
            "DELETE FROM protect_motion_events WHERE id IN (\
             SELECT id FROM protect_motion_events ORDER BY received_at_ms DESC, id DESC \
             LIMIT -1 OFFSET ?)",
            [MAX_MOTION_EVENTS],
        )?;
        transaction.commit()?;
        Ok(created)
    }

    pub fn motion_alerts(
        &self,
        limit: i64,
        include_matched: bool,
        now_ms: i64,
    ) -> AppResult<Vec<MotionEventRecord>> {
        let limit = limit.clamp(1, 250);
        let matched_filter = if include_matched {
            ""
        } else {
            "AND matched.id IS NULL"
        };
        let sql = format!(
            "SELECT event.id, event.camera_id, event.camera_name, event.event_ts_ms, \
             event.received_at_ms, event.evaluate_after_ms, event.expires_at_ms, \
             event.match_window_ms, event.delivery_method, event.alarm_name, \
             event.device_identifiers, matched.id, matched.ts_ms \
             FROM protect_motion_events event LEFT JOIN transactions matched ON matched.id=(\
             SELECT candidate.id FROM transactions candidate WHERE candidate.camera_id=event.camera_id \
             AND candidate.ts_ms BETWEEN event.event_ts_ms-event.match_window_ms \
             AND event.event_ts_ms+event.match_window_ms \
             ORDER BY ABS(candidate.ts_ms-event.event_ts_ms), candidate.id LIMIT 1) \
             WHERE event.expires_at_ms > ? {matched_filter} \
             ORDER BY event.event_ts_ms DESC, event.id DESC LIMIT ?"
        );
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "DELETE FROM protect_motion_events WHERE expires_at_ms <= ?",
            [now_ms],
        )?;
        let rows = {
            let mut statement = transaction.prepare(&sql)?;
            let mapped = statement.query_map(params![now_ms, limit], |row| {
                let device_identifiers_json: String = row.get(10)?;
                let matched_transaction_id: Option<String> = row.get(11)?;
                let matched_transaction_ts_ms: Option<i64> = row.get(12)?;
                let evaluate_after_ms: i64 = row.get(5)?;
                let event_ts_ms: i64 = row.get(3)?;
                Ok(MotionEventRecord {
                    id: row.get(0)?,
                    camera_id: row.get(1)?,
                    camera_name: row.get(2)?,
                    event_ts_ms,
                    received_at_ms: row.get(4)?,
                    evaluate_after_ms,
                    expires_at_ms: row.get(6)?,
                    match_window_ms: row.get(7)?,
                    delivery_method: row.get(8)?,
                    alarm_name: row.get(9)?,
                    device_identifiers: serde_json::from_str(&device_identifiers_json)
                        .unwrap_or_default(),
                    state: if matched_transaction_id.is_some() {
                        "matched".into()
                    } else if now_ms < evaluate_after_ms {
                        "pending".into()
                    } else {
                        "flagged".into()
                    },
                    transaction_delta_ms: matched_transaction_ts_ms
                        .map(|timestamp| timestamp - event_ts_ms),
                    matched_transaction_id,
                    matched_transaction_ts_ms,
                })
            })?;
            mapped.collect::<Result<Vec<_>, _>>()?
        };
        transaction.commit()?;
        Ok(rows)
    }

    pub fn motion_summary(&self, now_ms: i64) -> AppResult<Value> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "DELETE FROM protect_motion_events WHERE expires_at_ms <= ?",
            [now_ms],
        )?;
        let counts: (i64, i64, i64) = transaction.query_row(
            "SELECT \
             COALESCE(SUM(CASE WHEN matched.id IS NOT NULL THEN 1 ELSE 0 END), 0), \
             COALESCE(SUM(CASE WHEN matched.id IS NULL AND event.evaluate_after_ms > ? THEN 1 ELSE 0 END), 0), \
             COALESCE(SUM(CASE WHEN matched.id IS NULL AND event.evaluate_after_ms <= ? THEN 1 ELSE 0 END), 0) \
             FROM protect_motion_events event LEFT JOIN transactions matched ON matched.id=(\
             SELECT candidate.id FROM transactions candidate WHERE candidate.camera_id=event.camera_id \
             AND candidate.ts_ms BETWEEN event.event_ts_ms-event.match_window_ms \
             AND event.event_ts_ms+event.match_window_ms \
             ORDER BY ABS(candidate.ts_ms-event.event_ts_ms), candidate.id LIMIT 1) \
             WHERE event.expires_at_ms > ?",
            params![now_ms, now_ms, now_ms],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        transaction.commit()?;
        Ok(json!({
            "matched": counts.0,
            "pending": counts.1,
            "flagged": counts.2,
        }))
    }

    fn reconcile_missing_thumbnails(&self) -> AppResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let paths = {
            let mut statement = transaction.prepare(
                "SELECT id, thumbnail_path FROM transactions WHERE thumbnail_path IS NOT NULL",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        for (id, relative) in paths {
            let path = self.inner.thumbnail_dir.join(&relative);
            let metadata = is_local_filename(&relative)
                .then(|| fs::symlink_metadata(&path).ok())
                .flatten()
                .filter(|metadata| metadata.file_type().is_file());
            if let Some(metadata) = metadata {
                transaction.execute(
                    "UPDATE transactions SET thumbnail_bytes=COALESCE(thumbnail_bytes, ?) \
                     WHERE id=? AND thumbnail_path=?",
                    params![metadata.len() as i64, id, relative],
                )?;
            } else {
                transaction.execute(
                    "UPDATE transactions SET thumbnail_path=NULL, thumbnail_bytes=NULL, \
                     thumbnail_policy_revision=0 WHERE id=?",
                    [&id],
                )?;
            }
        }
        transaction.execute(
            "INSERT OR IGNORE INTO thumbnail_retries (transaction_id) \
             SELECT id FROM transactions WHERE camera_id IS NOT NULL \
             AND thumbnail_path IS NULL AND thumbnail_retired_at IS NULL",
            [],
        )?;
        transaction.commit()?;
        Ok(())
    }
}

fn migrate_schema(connection: &mut Connection) -> AppResult<()> {
    // The small bootstrap deliberately contains no indexes or triggers. Old
    // tables may be missing columns referenced by the current schema, so add
    // those columns before executing the complete schema.
    connection.execute_batch(MIGRATION_BOOTSTRAP_SCHEMA)?;
    migrate_legacy_columns(connection)?;
    connection.execute_batch(CURRENT_SCHEMA)?;
    migrate_legacy_auth(connection)?;
    migrate_legacy_snapshots(connection)?;
    connection.execute_batch(CURRENT_SCHEMA)?;
    Ok(())
}

fn migrate_legacy_columns(connection: &mut Connection) -> AppResult<()> {
    let columns = table_columns(connection, "transactions")?;
    let migrations = [
        (
            "updated_at",
            "ALTER TABLE transactions ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''",
        ),
        (
            "updated_ts_ms",
            "ALTER TABLE transactions ADD COLUMN updated_ts_ms INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "refunded_amount",
            "ALTER TABLE transactions ADD COLUMN refunded_amount INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "device_id",
            "ALTER TABLE transactions ADD COLUMN device_id TEXT NOT NULL DEFAULT ''",
        ),
        (
            "device_name",
            "ALTER TABLE transactions ADD COLUMN device_name TEXT NOT NULL DEFAULT ''",
        ),
        (
            "note",
            "ALTER TABLE transactions ADD COLUMN note TEXT NOT NULL DEFAULT ''",
        ),
        (
            "note_revision",
            "ALTER TABLE transactions ADD COLUMN note_revision INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "thumbnail_bytes",
            "ALTER TABLE transactions ADD COLUMN thumbnail_bytes INTEGER",
        ),
        (
            "thumbnail_policy_revision",
            "ALTER TABLE transactions ADD COLUMN thumbnail_policy_revision INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "thumbnail_retired_at",
            "ALTER TABLE transactions ADD COLUMN thumbnail_retired_at INTEGER",
        ),
        (
            "thumbnail_retired_reason",
            "ALTER TABLE transactions ADD COLUMN thumbnail_retired_reason TEXT NOT NULL DEFAULT ''",
        ),
        (
            "alarm_state",
            "ALTER TABLE transactions ADD COLUMN alarm_state TEXT NOT NULL DEFAULT 'sent'",
        ),
        (
            "alarm_claim_token",
            "ALTER TABLE transactions ADD COLUMN alarm_claim_token TEXT",
        ),
        (
            "alarm_claimed_at",
            "ALTER TABLE transactions ADD COLUMN alarm_claimed_at REAL",
        ),
        (
            "alarm_delivered_at_ms",
            "ALTER TABLE transactions ADD COLUMN alarm_delivered_at_ms INTEGER",
        ),
    ];
    for (column, sql) in migrations {
        if !columns.contains(column) {
            connection.execute(sql, [])?;
        }
    }
    connection.execute(
        "UPDATE transactions SET updated_at=created_at WHERE updated_at=''",
        [],
    )?;
    connection.execute(
        "UPDATE transactions SET updated_ts_ms=ts_ms WHERE updated_ts_ms=0",
        [],
    )?;
    connection.execute("UPDATE transactions SET raw='{}'", [])?;

    let map_columns = table_columns(connection, "camera_map")?;
    if !map_columns.is_empty() && !map_columns.contains("device_id") {
        let transaction = connection.transaction()?;
        transaction.execute("ALTER TABLE camera_map RENAME TO camera_map_legacy", [])?;
        transaction.execute_batch(
            "CREATE TABLE camera_map (location_id TEXT NOT NULL, device_id TEXT NOT NULL DEFAULT '', \
             device_name TEXT NOT NULL DEFAULT '', camera_id TEXT NOT NULL, camera_name TEXT NOT NULL DEFAULT '', \
             PRIMARY KEY(location_id, device_id));",
        )?;
        transaction.execute(
            "INSERT INTO camera_map (location_id, device_id, device_name, camera_id, camera_name) \
             SELECT location_id, '', '', camera_id, camera_name FROM camera_map_legacy",
            [],
        )?;
        transaction.execute("DROP TABLE camera_map_legacy", [])?;
        transaction.commit()?;
    }
    Ok(())
}

fn migrate_legacy_auth(connection: &mut Connection) -> AppResult<()> {
    let user_columns = table_columns(connection, "users")?;
    if !user_columns.is_empty() && !user_columns.contains("auth_revision") {
        connection.execute(
            "ALTER TABLE users ADD COLUMN auth_revision INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    let legacy_hash: Option<String> = connection
        .query_row(
            "SELECT value FROM settings WHERE key='admin.password_hash' AND encrypted=0",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let user_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
    if let Some(hash) = legacy_hash.as_deref().filter(|_| user_count == 0) {
        connection.execute(
            "INSERT INTO users (username, password_hash, role, enabled, created_at) \
             VALUES ('admin', ?, 'admin', 1, ?)",
            params![hash, now_seconds()],
        )?;
    }

    let admin: Option<(i64, String)> = connection
        .query_row(
            "SELECT id, role FROM users WHERE username='admin' COLLATE NOCASE",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let session_columns = table_columns(connection, "sessions")?;
    if !session_columns.contains("user_id") {
        connection.execute("ALTER TABLE sessions RENAME TO sessions_legacy", [])?;
        connection.execute_batch(
            "CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, \
             expires_at REAL NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);",
        )?;
        if let Some((admin_id, _)) = admin.as_ref().filter(|(_, role)| role == ROLE_ADMIN) {
            connection.execute(
                "INSERT INTO sessions (token_hash, user_id, expires_at) \
                 SELECT token_hash, ?, expires_at FROM sessions_legacy",
                [admin_id],
            )?;
        }
        connection.execute("DROP TABLE sessions_legacy", [])?;
    }
    connection.execute(
        "DELETE FROM sessions WHERE NOT EXISTS (SELECT 1 FROM users \
         WHERE users.id=sessions.user_id AND users.enabled=1)",
        [],
    )?;
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)",
        [],
    )?;
    if legacy_hash.is_some() && admin.is_some_and(|(_, role)| role == ROLE_ADMIN) {
        connection.execute("DELETE FROM settings WHERE key='admin.password_hash'", [])?;
    }
    Ok(())
}

fn migrate_legacy_snapshots(connection: &mut Connection) -> AppResult<()> {
    let columns = table_columns(connection, "transaction_feed_snapshots")?;
    if columns.is_empty() {
        return Ok(());
    }
    if columns.contains("filter_signature") {
        connection.execute(
            "DELETE FROM transaction_feed_snapshots WHERE filter_signature != '' \
             AND filter_signature NOT LIKE 'hmac-sha256-v2:%'",
            [],
        )?;
        return Ok(());
    }
    connection.execute(
        "ALTER TABLE transaction_feed_snapshots RENAME TO transaction_feed_snapshots_legacy",
        [],
    )?;
    connection.execute_batch(
        "CREATE TABLE transaction_feed_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_revision INTEGER NOT NULL,
            rowid_boundary INTEGER NOT NULL,
            filter_signature TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            last_accessed_at REAL NOT NULL,
            UNIQUE (order_revision, rowid_boundary, filter_signature)
        );",
    )?;
    connection.execute(
        "INSERT INTO transaction_feed_snapshots \
         (id, order_revision, rowid_boundary, filter_signature, created_at, last_accessed_at) \
         SELECT id, order_revision, rowid_boundary, '', created_at, last_accessed_at \
         FROM transaction_feed_snapshots_legacy",
        [],
    )?;
    connection.execute("DROP TABLE transaction_feed_snapshots_legacy", [])?;
    Ok(())
}

fn table_columns(connection: &Connection, table: &str) -> AppResult<HashSet<String>> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = statement.query_map([], |row| row.get(1))?;
    rows.collect::<Result<_, _>>().map_err(Into::into)
}

fn setting_value(
    connection: &Connection,
    cipher: &CredentialCipher,
    key: &str,
) -> AppResult<Option<String>> {
    let row = connection
        .query_row(
            "SELECT value, encrypted FROM settings WHERE key = ?",
            [key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? != 0)),
        )
        .optional()?;
    match row {
        Some((value, true)) => Ok(Some(cipher.decrypt(&value)?)),
        Some((value, false)) => Ok(Some(value)),
        None => Ok(None),
    }
}

fn square_oauth_snapshot_locked(
    connection: &Connection,
    cipher: &CredentialCipher,
) -> AppResult<SquareOAuthSnapshot> {
    Ok(SquareOAuthSnapshot {
        access_token: setting_value(connection, cipher, "square.access_token")?,
        refresh_token: setting_value(connection, cipher, "square.refresh_token")?,
        token_expires_at: setting_value(connection, cipher, "square.token_expires_at")?,
        environment: setting_value(connection, cipher, "square.environment")?,
        merchant_id: setting_value(connection, cipher, "square.merchant_id")?,
        account_revision: setting_value(connection, cipher, SQUARE_ACCOUNT_REVISION_SETTING)?,
        client_id: setting_value(connection, cipher, "square.oauth_client_id")?,
        client_secret: setting_value(connection, cipher, "square.oauth_client_secret")?,
    })
}

fn write_setting(
    transaction: &Transaction<'_>,
    cipher: &CredentialCipher,
    key: &str,
    value: &str,
    secret: bool,
) -> AppResult<()> {
    let value = if secret {
        cipher.encrypt(value)
    } else {
        value.to_owned()
    };
    transaction.execute(
        "INSERT INTO settings (key, value, encrypted) VALUES (?, ?, ?) \
         ON CONFLICT(key) DO UPDATE SET value=excluded.value, encrypted=excluded.encrypted",
        params![key, value, i64::from(secret)],
    )?;
    Ok(())
}

fn write_plain_setting(transaction: &Transaction<'_>, key: &str, value: i64) -> AppResult<()> {
    transaction.execute(
        "INSERT INTO settings (key, value, encrypted) VALUES (?, ?, 0) \
         ON CONFLICT(key) DO UPDATE SET value=excluded.value, encrypted=0",
        params![key, value.to_string()],
    )?;
    Ok(())
}

fn increment_plain_setting(transaction: &Transaction<'_>, key: &str) -> AppResult<()> {
    transaction.execute(
        "INSERT INTO settings (key, value, encrypted) VALUES (?, '1', 0) \
         ON CONFLICT(key) DO UPDATE SET value=CAST(COALESCE(NULLIF(settings.value, ''), '0') AS INTEGER)+1, encrypted=0",
        [key],
    )?;
    Ok(())
}

fn max_plain_setting(transaction: &Transaction<'_>, key: &str, value: i64) -> AppResult<()> {
    transaction.execute(
        "INSERT INTO settings (key, value, encrypted) VALUES (?, ?, 0) \
         ON CONFLICT(key) DO UPDATE SET value=MAX(CAST(settings.value AS INTEGER), CAST(excluded.value AS INTEGER)), encrypted=0",
        params![key, value.to_string()],
    )?;
    Ok(())
}

fn map_login_audit(row: &Row<'_>) -> rusqlite::Result<LoginAuditRecord> {
    Ok(LoginAuditRecord {
        id: row.get(0)?,
        user_id: row.get(1)?,
        username: row.get(2)?,
        role: row.get(3)?,
        client_ip: row.get(4)?,
        logged_in_at: row.get(5)?,
    })
}

fn map_transaction(row: &Row<'_>) -> rusqlite::Result<TransactionRecord> {
    Ok(TransactionRecord {
        id: row.get("id")?,
        created_at: row.get("created_at")?,
        ts_ms: row.get("ts_ms")?,
        updated_at: row.get("updated_at")?,
        updated_ts_ms: row.get("updated_ts_ms")?,
        amount: row.get("amount")?,
        currency: row.get("currency")?,
        refunded_amount: row.get("refunded_amount")?,
        status: row.get("status")?,
        location_id: row.get("location_id")?,
        device_id: row.get("device_id")?,
        device_name: row.get("device_name")?,
        card_last4: row.get("card_last4")?,
        receipt_url: row.get("receipt_url")?,
        camera_id: row.get("camera_id")?,
        thumbnail_path: row.get("thumbnail_path")?,
        note: row.get("note")?,
        note_revision: row.get("note_revision")?,
        thumbnail_bytes: row.get("thumbnail_bytes")?,
        thumbnail_policy_revision: row.get("thumbnail_policy_revision")?,
        thumbnail_retired_at: row.get("thumbnail_retired_at")?,
        thumbnail_retired_reason: row.get("thumbnail_retired_reason")?,
        alarm_state: row.get("alarm_state")?,
        alarm_delivered_at_ms: row.get("alarm_delivered_at_ms")?,
        thumbnail_retry_attempts: row.get("thumbnail_retry_attempts")?,
    })
}

fn camera_for_location(
    connection: &Connection,
    location_id: &str,
    device_id: &str,
) -> AppResult<Option<CameraMappingEntry>> {
    connection
        .query_row(
            "SELECT location_id, device_id, device_name, camera_id, camera_name \
             FROM camera_map WHERE (location_id=? AND device_id=?) \
             OR (location_id=? AND device_id='') OR (location_id='*' AND device_id='') \
             ORDER BY CASE WHEN location_id=? AND device_id=? THEN 0 \
             WHEN location_id=? AND device_id='' THEN 1 ELSE 2 END LIMIT 1",
            params![
                location_id,
                device_id,
                location_id,
                location_id,
                device_id,
                location_id
            ],
            |row| {
                Ok(CameraMappingEntry {
                    location_id: row.get(0)?,
                    device_id: row.get(1)?,
                    device_name: row.get(2)?,
                    camera_id: row.get(3)?,
                    camera_name: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn requeue_changed_thumbnail_locked(
    transaction: &Transaction<'_>,
    transaction_id: &str,
    lease_token: &str,
) -> AppResult<()> {
    let runnable = transaction
        .query_row(
            "SELECT camera_id IS NOT NULL AND thumbnail_path IS NULL \
             AND thumbnail_retired_at IS NULL FROM transactions WHERE id=?",
            [transaction_id],
            |row| row.get::<_, bool>(0),
        )
        .optional()?
        .unwrap_or(false);
    if runnable {
        transaction.execute(
            "UPDATE thumbnail_retries SET attempts=0, next_attempt_at=0, \
             lease_token=NULL, lease_expires_at=NULL, last_error='' \
             WHERE transaction_id=? AND lease_token=?",
            params![transaction_id, lease_token],
        )?;
    } else {
        transaction.execute(
            "DELETE FROM thumbnail_retries WHERE transaction_id=? AND lease_token=?",
            params![transaction_id, lease_token],
        )?;
    }
    Ok(())
}

fn transaction_filter(
    query: &str,
    status: &str,
    cipher: &CredentialCipher,
) -> AppResult<(String, String, Vec<SqlValue>)> {
    let query = query.trim();
    let status = status.trim().to_ascii_uppercase();
    if query.len() > 64 || has_forbidden_controls(query, false) {
        return Err(AppError::Unprocessable(
            "Invalid transaction search query".into(),
        ));
    }
    if !status.is_empty()
        && !matches!(
            status.as_str(),
            "APPROVED" | "PENDING" | "COMPLETED" | "CANCELED" | "FAILED"
        )
    {
        return Err(AppError::Unprocessable(
            "Invalid transaction status filter".into(),
        ));
    }
    if query.is_empty() && status.is_empty() {
        return Ok((String::new(), String::new(), Vec::new()));
    }
    let canonical = serde_json::to_vec(&(query, status.as_str())).map_err(AppError::internal)?;
    let signature = format!(
        "{TRANSACTION_FILTER_SIGNATURE_PREFIX}{}",
        cipher.keyed_hmac_hex(TRANSACTION_FILTER_SIGNATURE_DOMAIN, &canonical)?
    );
    let mut clauses = Vec::new();
    let mut values = Vec::new();
    if !query.is_empty() {
        let escaped = query
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pattern = format!("%{escaped}%");
        clauses.push(
            "(t.id LIKE ? ESCAPE '\\' COLLATE NOCASE OR \
             t.card_last4 LIKE ? ESCAPE '\\' COLLATE NOCASE OR \
             t.device_id LIKE ? ESCAPE '\\' COLLATE NOCASE OR \
             t.device_name LIKE ? ESCAPE '\\' COLLATE NOCASE OR \
             t.location_id LIKE ? ESCAPE '\\' COLLATE NOCASE OR \
             t.status LIKE ? ESCAPE '\\' COLLATE NOCASE OR \
             t.note LIKE ? ESCAPE '\\' COLLATE NOCASE)"
                .to_owned(),
        );
        values.extend((0..7).map(|_| SqlValue::Text(pattern.clone())));
    }
    if !status.is_empty() {
        clauses.push("t.status = ?".to_owned());
        values.push(SqlValue::Text(status));
    }
    Ok((signature, format!("AND {}", clauses.join(" AND ")), values))
}

fn motion_config_locked(
    connection: &Connection,
    cipher: &CredentialCipher,
) -> AppResult<MotionConfigSecret> {
    let token =
        setting_value(connection, cipher, MOTION_WEBHOOK_TOKEN_SETTING)?.unwrap_or_default();
    let camera_id =
        setting_value(connection, cipher, MOTION_CAMERA_ID_SETTING)?.unwrap_or_default();
    let camera_name =
        setting_value(connection, cipher, MOTION_CAMERA_NAME_SETTING)?.unwrap_or_default();
    let bounded = |key: &str, default: i64, low: i64, high: i64| -> AppResult<i64> {
        Ok(setting_value(connection, cipher, key)?
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| (low..=high).contains(value))
            .unwrap_or(default))
    };
    Ok(MotionConfigSecret {
        public: MotionConfig {
            enabled: !token.is_empty() && !camera_id.is_empty(),
            camera_id,
            camera_name,
            match_window_seconds: bounded(MOTION_MATCH_WINDOW_SETTING, 15, 1, 300)?,
            grace_seconds: bounded(MOTION_GRACE_SETTING, 90, 0, 600)?,
            retention_days: bounded(MOTION_RETENTION_SETTING, 30, 1, 365)?,
            token_configured: !token.is_empty(),
            last_event_ms: None,
        },
        token,
    })
}

fn suppress_historical_alarm(
    transaction: &Transaction<'_>,
    payment: &PaymentFacts,
    existing: Option<&ExistingPayment>,
) -> AppResult<()> {
    let enabled_after = transaction
        .query_row(
            "SELECT value FROM settings WHERE key=? AND encrypted=0",
            [ALARM_ENABLED_AFTER_SETTING],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .and_then(|value| value.parse::<i64>().ok());
    let completion_reference = if payment.status.eq_ignore_ascii_case("COMPLETED") {
        match existing {
            None => Some(payment.ts_ms),
            Some(value) if !value.status.eq_ignore_ascii_case("COMPLETED") => {
                Some(payment.updated_ts_ms)
            }
            _ => None,
        }
    } else {
        None
    };
    if completion_reference
        .is_some_and(|value| enabled_after.is_none_or(|boundary| value < boundary))
    {
        transaction.execute(
            "UPDATE transactions SET alarm_state='sent', alarm_claim_token=NULL, alarm_claimed_at=NULL \
             WHERE id=? AND alarm_state!='sent'",
            [&payment.id],
        )?;
    }
    Ok(())
}

pub fn normalize_username(value: &str) -> AppResult<String> {
    let username = value.trim();
    if !(1..=64).contains(&username.len()) {
        return Err(AppError::Unprocessable(
            "Username must be 1 to 64 characters".into(),
        ));
    }
    let mut characters = username.chars();
    if !characters
        .next()
        .is_some_and(|value| value.is_ascii_alphanumeric())
        || !username
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || ".-_".contains(value))
    {
        return Err(AppError::Unprocessable(
            "Username can contain only ASCII letters, numbers, dot, dash, and underscore".into(),
        ));
    }
    Ok(username.to_owned())
}

fn validate_mapping(mapping: &CameraMappingEntry) -> AppResult<()> {
    if mapping.location_id.is_empty()
        || mapping.location_id.len() > 64
        || mapping.device_id.len() > 255
        || mapping.device_name.len() > 255
        || mapping.camera_name.len() > 128
    {
        return Err(AppError::Unprocessable("Invalid camera mapping".into()));
    }
    validate_camera_id(&mapping.camera_id)
}

pub fn validate_camera_id(value: &str) -> AppResult<()> {
    if !(1..=64).contains(&value.len())
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
    {
        return Err(AppError::Unprocessable("Invalid Protect camera id".into()));
    }
    Ok(())
}

fn validate_payment(payment: &PaymentFacts) -> AppResult<()> {
    if payment.id.is_empty()
        || payment.id.len() > 256
        || payment.created_at.is_empty()
        || payment.updated_at.is_empty()
        || payment.ts_ms < 0
        || payment.updated_ts_ms < 0
        || payment.refunded_amount < 0
    {
        return Err(AppError::Unprocessable("Invalid Square payment".into()));
    }
    Ok(())
}

fn validate_note(note: &str) -> AppResult<()> {
    if note.chars().count() > 2000 || has_forbidden_controls(note, true) {
        return Err(AppError::Unprocessable(
            "Transaction note contains unsupported characters".into(),
        ));
    }
    Ok(())
}

fn has_forbidden_controls(value: &str, allow_whitespace: bool) -> bool {
    value.chars().any(|character| {
        let code = character as u32;
        (code < 32 && !(allow_whitespace && matches!(character, '\r' | '\n' | '\t'))) || code == 127
    })
}

fn constant_time_text_equal(left: &str, right: &str) -> bool {
    left.len() == right.len() && bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

fn now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

pub fn now_millis() -> i64 {
    (now_seconds() * 1000.0) as i64
}

fn is_local_filename(value: &str) -> bool {
    !value.is_empty()
        && Path::new(value)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == value)
}

fn regular_file_size(path: &Path) -> AppResult<i64> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(AppError::BadRequest(
            "Thumbnail is not a regular file".into(),
        ));
    }
    i64::try_from(metadata.len()).map_err(AppError::internal)
}

fn clean_interrupted_thumbnail_writes(directory: &Path) -> AppResult<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') && name.ends_with(".tmp") && entry.file_type()?.is_file() {
            fs::remove_file(entry.path())?;
        } else if entry.file_type()?.is_file() {
            secure_file(&entry.path())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{hash_password, hash_session_token, verify_password};
    use crate::thumbnail::write_thumbnail;

    const TEST_CAMERA_ID: &str = "cam1aaaaaaaaaaaaaaaaaaaaa";

    fn add_thumbnail_asset(store: &Store, id: &str, ts_ms: i64, bytes: &[u8]) -> PathBuf {
        store
            .replace_camera_mappings(&[CameraMappingEntry {
                location_id: "LOC_1".into(),
                device_id: String::new(),
                device_name: String::new(),
                camera_id: TEST_CAMERA_ID.into(),
                camera_name: "Counter".into(),
            }])
            .unwrap();
        store
            .upsert_payment(&PaymentFacts {
                id: id.into(),
                created_at: "2027-01-15T08:00:00.000Z".into(),
                ts_ms,
                updated_at: "2027-01-15T08:00:00.000Z".into(),
                updated_ts_ms: ts_ms,
                amount: 99,
                currency: "USD".into(),
                status: "COMPLETED".into(),
                location_id: "LOC_1".into(),
                ..PaymentFacts::default()
            })
            .unwrap();
        let filename = format!("{id}.jpg");
        let path = store.thumbnail_dir().join(&filename);
        write_thumbnail(&path, bytes).unwrap();
        assert!(
            store
                .attach_thumbnail(id, TEST_CAMERA_ID, ts_ms, &filename, bytes.len() as i64, 0,)
                .unwrap()
        );
        path
    }

    #[test]
    fn opens_new_store_and_persists_sessions() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        let hash = hash_password("a-long-test-password").unwrap();
        assert!(store.create_initial_admin(&hash).unwrap());
        let user = store.user_for_login("ADMIN").unwrap().unwrap();
        assert!(verify_password("a-long-test-password", &user.password_hash));
        let token = new_session_token();
        store
            .create_session(&token, user.id, user.auth_revision, "127.0.0.1")
            .unwrap();
        assert_eq!(
            store.session_user(&token).unwrap().unwrap().role,
            ROLE_ADMIN
        );
    }

    #[test]
    fn notes_are_optimistically_concurrent_and_searchable() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        store
            .upsert_payment(&PaymentFacts {
                id: "PAY_1".into(),
                created_at: "2026-07-16T15:30:00.000Z".into(),
                ts_ms: 1_784_213_400_000,
                updated_at: "2026-07-16T15:30:00.000Z".into(),
                updated_ts_ms: 1_784_213_400_000,
                amount: 99,
                currency: "USD".into(),
                status: "COMPLETED".into(),
                ..PaymentFacts::default()
            })
            .unwrap();
        assert_eq!(
            store
                .set_transaction_note("PAY_1", "manual review", 0)
                .unwrap(),
            Some(("manual review".into(), 1))
        );
        assert!(matches!(
            store.set_transaction_note("PAY_1", "stale", 0),
            Err(AppError::Conflict(_))
        ));
        let (rows, _) = store
            .list_transactions_page(50, 0, None, "manual", "")
            .unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn migrates_legacy_admin_and_sessions() {
        let temp = tempfile::tempdir().unwrap();
        let password_hash = hash_password("a-long-test-password").unwrap();
        let token = "legacy-session-token";
        {
            let connection = Connection::open(temp.path().join("spi.db")).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE settings (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        encrypted INTEGER NOT NULL DEFAULT 0
                    );
                    CREATE TABLE sessions (
                        token_hash TEXT PRIMARY KEY,
                        expires_at REAL NOT NULL
                    );",
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO settings (key, value, encrypted) VALUES ('admin.password_hash', ?, 0)",
                    [&password_hash],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO sessions (token_hash, expires_at) VALUES (?, ?)",
                    params![hash_session_token(token), now_seconds() + 3600.0],
                )
                .unwrap();
        }

        let store = Store::open(temp.path()).unwrap();
        let admin = store.user_for_login("ADMIN").unwrap().unwrap();
        assert_eq!(admin.role, ROLE_ADMIN);
        assert_eq!(
            store.session_user(token).unwrap().unwrap().username,
            DEFAULT_ADMIN_USERNAME
        );
        assert!(store.get_setting("admin.password_hash").unwrap().is_none());
        let columns = table_columns(&store.connection().unwrap(), "sessions").unwrap();
        assert_eq!(
            columns,
            HashSet::from([
                "token_hash".to_owned(),
                "user_id".to_owned(),
                "expires_at".to_owned()
            ])
        );
    }

    #[test]
    fn migrates_legacy_transactions_before_creating_indexes() {
        let temp = tempfile::tempdir().unwrap();
        let thumbnails = temp.path().join("thumbnails");
        fs::create_dir(&thumbnails).unwrap();
        fs::write(thumbnails.join("PAY_LEGACY.jpg"), b"legacy-image").unwrap();
        {
            let connection = Connection::open(temp.path().join("spi.db")).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE transactions (
                        id TEXT PRIMARY KEY,
                        created_at TEXT NOT NULL,
                        ts_ms INTEGER NOT NULL,
                        amount INTEGER NOT NULL,
                        currency TEXT NOT NULL,
                        status TEXT NOT NULL,
                        location_id TEXT NOT NULL DEFAULT '',
                        card_last4 TEXT NOT NULL DEFAULT '',
                        receipt_url TEXT NOT NULL DEFAULT '',
                        camera_id TEXT,
                        thumbnail_path TEXT,
                        raw TEXT NOT NULL DEFAULT '{}'
                    );",
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO transactions (
                        id, created_at, ts_ms, amount, currency, status, location_id,
                        card_last4, receipt_url, camera_id, thumbnail_path, raw
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    params![
                        "PAY_LEGACY",
                        "2026-07-16T14:00:00.000Z",
                        1_784_208_000_000_i64,
                        99_i64,
                        "USD",
                        "COMPLETED",
                        "LOC_1",
                        "4242",
                        "https://example.invalid/receipt",
                        "cam1aaaaaaaaaaaaaaaaaaaaa",
                        "PAY_LEGACY.jpg",
                        r#"{"buyer_email_address":"private@example.invalid"}"#,
                    ],
                )
                .unwrap();
        }

        let store = Store::open(temp.path()).unwrap();
        let payment = store.get_transaction("PAY_LEGACY").unwrap().unwrap();
        assert_eq!(payment.updated_at, payment.created_at);
        assert_eq!(payment.updated_ts_ms, payment.ts_ms);
        assert_eq!(payment.thumbnail_bytes, Some(12));
        let raw: String = store
            .connection()
            .unwrap()
            .query_row(
                "SELECT raw FROM transactions WHERE id='PAY_LEGACY'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(raw, "{}");
    }

    #[test]
    fn thumbnail_retention_uses_age_and_quota_reasons() {
        const NOW: i64 = 1_800_000_000_000;
        const DAY: i64 = 86_400_000;
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        let old = add_thumbnail_asset(&store, "OLD", NOW - 3 * DAY, b"old-image");
        let recent = add_thumbnail_asset(&store, "RECENT", NOW, b"recent-image");
        store.update_thumbnail_policy(false, 72, 960, 1, 0).unwrap();
        let result = store.run_thumbnail_maintenance(false, NOW).unwrap();
        assert_eq!(result["retired_age_count"], 1);
        assert_eq!(
            store
                .get_transaction("OLD")
                .unwrap()
                .unwrap()
                .thumbnail_retired_reason,
            "age"
        );
        assert!(!old.exists());
        assert!(recent.exists());

        let quota_store = Store::open(temp.path().join("quota")).unwrap();
        for index in 0..3 {
            add_thumbnail_asset(
                &quota_store,
                &format!("Q{index}"),
                NOW + index,
                &vec![index as u8; 600 * 1024],
            );
        }
        quota_store
            .update_thumbnail_policy(false, 72, 960, 0, 1)
            .unwrap();
        let result = quota_store
            .run_thumbnail_maintenance(false, NOW + 10)
            .unwrap();
        assert_eq!(result["retired_quota_count"], 2);
        assert_eq!(result["active_count"], 1);
        assert_eq!(result["after_bytes"], 600 * 1024);
    }

    #[test]
    fn retention_only_policy_change_does_not_force_recompression() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        let first = store.update_thumbnail_policy(true, 72, 960, 0, 0).unwrap();
        let second = store.update_thumbnail_policy(true, 72, 960, 30, 0).unwrap();
        let third = store.update_thumbnail_policy(true, 60, 960, 30, 0).unwrap();
        assert_eq!(second, first);
        assert_eq!(third, first + 1);
    }

    #[test]
    fn overlap_poll_does_not_recreate_retired_thumbnail_bytes() {
        const NOW: i64 = 1_800_000_000_000;
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        add_thumbnail_asset(&store, "PAY_RETIRED", NOW - 2 * 86_400_000, b"image");
        store.update_thumbnail_policy(false, 72, 960, 1, 0).unwrap();
        store.run_thumbnail_maintenance(false, NOW).unwrap();
        store
            .upsert_payment(&PaymentFacts {
                id: "PAY_RETIRED".into(),
                created_at: "2027-01-15T08:00:00.000Z".into(),
                ts_ms: NOW - 2 * 86_400_000,
                updated_at: "2027-01-15T08:01:00.000Z".into(),
                updated_ts_ms: NOW + 60_000,
                amount: 99,
                currency: "USD".into(),
                status: "COMPLETED".into(),
                location_id: "LOC_1".into(),
                ..PaymentFacts::default()
            })
            .unwrap();
        let transaction = store.get_transaction("PAY_RETIRED").unwrap().unwrap();
        assert!(transaction.thumbnail_retired_at.is_some());
        assert!(transaction.thumbnail_path.is_none());
        assert!(
            store
                .claim_due_thumbnail_retries(10, 100.0)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn protect_switch_retires_old_transactions_from_future_remapping() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        let path = add_thumbnail_asset(&store, "PAY_SWITCH", 1_800_000_000_000, b"image");
        let guard = store.integration_guard(true).unwrap();
        store.clear_protect_evidence_under_guard().unwrap();
        drop(guard);
        assert!(!path.exists());

        store
            .replace_camera_mappings(&[CameraMappingEntry {
                location_id: "LOC_1".into(),
                device_id: String::new(),
                device_name: String::new(),
                camera_id: "cam2bbbbbbbbbbbbbbbbbbbbb".into(),
                camera_name: "New Counter".into(),
            }])
            .unwrap();
        store
            .upsert_payment(&PaymentFacts {
                id: "PAY_SWITCH".into(),
                created_at: "2027-01-15T08:00:00.000Z".into(),
                ts_ms: 1_800_000_000_000,
                updated_at: "2027-01-15T08:01:00.000Z".into(),
                updated_ts_ms: 1_800_000_060_000,
                amount: 99,
                currency: "USD".into(),
                status: "COMPLETED".into(),
                location_id: "LOC_1".into(),
                ..PaymentFacts::default()
            })
            .unwrap();
        let transaction = store.get_transaction("PAY_SWITCH").unwrap().unwrap();
        assert!(transaction.camera_id.is_none());
        assert!(transaction.thumbnail_path.is_none());
    }

    #[test]
    fn disabled_alarms_are_suppressed_and_enabled_alarms_are_leased() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        let facts = PaymentFacts {
            id: "PAY_ALARM_DISABLED".into(),
            created_at: "2027-01-15T08:00:00.000Z".into(),
            ts_ms: 1_800_000_000_000,
            updated_at: "2027-01-15T08:00:00.000Z".into(),
            updated_ts_ms: 1_800_000_000_000,
            amount: 99,
            currency: "USD".into(),
            status: "COMPLETED".into(),
            location_id: "LOC_1".into(),
            ..PaymentFacts::default()
        };
        store.upsert_payment(&facts).unwrap();
        assert_eq!(
            store
                .get_transaction("PAY_ALARM_DISABLED")
                .unwrap()
                .unwrap()
                .alarm_state,
            "sent"
        );

        store
            .set_setting(ALARM_ENABLED_AFTER_SETTING, "0", false)
            .unwrap();
        let mut enabled = facts;
        enabled.id = "PAY_ALARM_ENABLED".into();
        store.upsert_payment(&enabled).unwrap();
        let claim = store
            .claim_alarm_trigger("PAY_ALARM_ENABLED")
            .unwrap()
            .unwrap();
        assert!(
            store
                .claim_alarm_trigger("PAY_ALARM_ENABLED")
                .unwrap()
                .is_none()
        );
        assert!(
            !store
                .mark_alarm_sent("PAY_ALARM_ENABLED", "wrong-claim", 10)
                .unwrap()
        );
        assert!(
            store
                .mark_alarm_sent("PAY_ALARM_ENABLED", &claim, 10)
                .unwrap()
        );
    }

    #[test]
    fn thumbnail_retry_claim_prevents_concurrent_capture() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        store
            .replace_camera_mappings(&[CameraMappingEntry {
                location_id: "LOC_1".into(),
                device_id: String::new(),
                device_name: String::new(),
                camera_id: TEST_CAMERA_ID.into(),
                camera_name: "Counter".into(),
            }])
            .unwrap();
        store
            .upsert_payment(&PaymentFacts {
                id: "PAY_RETRY".into(),
                created_at: "2027-01-15T08:00:00.000Z".into(),
                ts_ms: 1_800_000_000_000,
                updated_at: "2027-01-15T08:00:00.000Z".into(),
                updated_ts_ms: 1_800_000_000_000,
                amount: 99,
                currency: "USD".into(),
                status: "COMPLETED".into(),
                location_id: "LOC_1".into(),
                ..PaymentFacts::default()
            })
            .unwrap();
        let claimed = store.claim_due_thumbnail_retries(10, 100.0).unwrap();
        assert_eq!(claimed.len(), 1);
        assert!(
            store
                .claim_due_thumbnail_retries(10, 100.0)
                .unwrap()
                .is_empty()
        );
        let lease = &claimed[0].1;
        assert!(
            !store
                .fail_thumbnail_retry(
                    "PAY_RETRY",
                    "wrong-lease",
                    TEST_CAMERA_ID,
                    1_800_000_000_000,
                    "failed",
                    100.0,
                )
                .unwrap()
        );
        assert!(
            store
                .fail_thumbnail_retry(
                    "PAY_RETRY",
                    lease,
                    TEST_CAMERA_ID,
                    1_800_000_000_000,
                    "failed",
                    100.0,
                )
                .unwrap()
        );
    }

    #[test]
    fn duplicate_payment_does_not_cancel_active_thumbnail_lease() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        store
            .replace_camera_mappings(&[CameraMappingEntry {
                location_id: "LOC_1".into(),
                device_id: "DEVICE_1".into(),
                device_name: "Register".into(),
                camera_id: TEST_CAMERA_ID.into(),
                camera_name: "Counter".into(),
            }])
            .unwrap();
        let mut facts = PaymentFacts {
            id: "PAY_LEASE_OVERLAP".into(),
            created_at: "2027-01-15T08:00:00.000Z".into(),
            ts_ms: 1_800_000_000_000,
            updated_at: "2027-01-15T08:00:00.000Z".into(),
            updated_ts_ms: 1_800_000_000_000,
            amount: 99,
            currency: "USD".into(),
            status: "COMPLETED".into(),
            location_id: "LOC_1".into(),
            device_id: "DEVICE_1".into(),
            ..PaymentFacts::default()
        };
        store.upsert_payment(&facts).unwrap();
        let first = store.claim_due_thumbnail_retries(1, 100.0).unwrap();
        assert_eq!(first.len(), 1);

        facts.updated_at = "2027-01-15T08:00:01.000Z".into();
        facts.updated_ts_ms += 1_000;
        facts.location_id.clear();
        facts.device_id.clear();
        store.upsert_payment(&facts).unwrap();
        assert!(
            store
                .claim_due_thumbnail_retries(1, 101.0)
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .fail_thumbnail_retry(
                    "PAY_LEASE_OVERLAP",
                    &first[0].1,
                    TEST_CAMERA_ID,
                    1_800_000_000_000,
                    "retry",
                    101.0,
                )
                .unwrap()
        );
        let stored = store.get_transaction("PAY_LEASE_OVERLAP").unwrap().unwrap();
        assert_eq!(stored.location_id, "LOC_1");
        assert_eq!(stored.device_id, "DEVICE_1");
    }

    #[test]
    fn expired_thumbnail_lease_cannot_commit_over_new_claim() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        store
            .replace_camera_mappings(&[CameraMappingEntry {
                location_id: "LOC_1".into(),
                device_id: String::new(),
                device_name: String::new(),
                camera_id: TEST_CAMERA_ID.into(),
                camera_name: "Counter".into(),
            }])
            .unwrap();
        store
            .upsert_payment(&PaymentFacts {
                id: "PAY_STALE_LEASE".into(),
                created_at: "2027-01-15T08:00:00.000Z".into(),
                ts_ms: 1_800_000_000_000,
                updated_at: "2027-01-15T08:00:00.000Z".into(),
                updated_ts_ms: 1_800_000_000_000,
                amount: 99,
                currency: "USD".into(),
                status: "COMPLETED".into(),
                location_id: "LOC_1".into(),
                ..PaymentFacts::default()
            })
            .unwrap();
        let stale = store.claim_due_thumbnail_retries(1, 100.0).unwrap();
        let current = store.claim_due_thumbnail_retries(1, 161.0).unwrap();
        assert_ne!(stale[0].1, current[0].1);
        assert!(
            !store
                .complete_thumbnail_retry(
                    "PAY_STALE_LEASE",
                    &stale[0].1,
                    TEST_CAMERA_ID,
                    1_800_000_000_000,
                    "stale.jpg",
                    10,
                    0,
                )
                .unwrap()
        );
        assert!(
            !store
                .fail_thumbnail_retry(
                    "PAY_STALE_LEASE",
                    &stale[0].1,
                    TEST_CAMERA_ID,
                    1_800_000_000_000,
                    "late",
                    161.0,
                )
                .unwrap()
        );
        assert!(
            store
                .complete_thumbnail_retry(
                    "PAY_STALE_LEASE",
                    &current[0].1,
                    TEST_CAMERA_ID,
                    1_800_000_000_000,
                    "current.jpg",
                    10,
                    0,
                )
                .unwrap()
        );
    }

    #[test]
    fn mapping_change_retargets_pending_thumbnail_and_fences_old_worker() {
        const CAMERA_B: &str = "cam2bbbbbbbbbbbbbbbbbbbbb";
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        store
            .replace_camera_mappings(&[CameraMappingEntry {
                location_id: "LOC_1".into(),
                device_id: String::new(),
                device_name: String::new(),
                camera_id: TEST_CAMERA_ID.into(),
                camera_name: "Old camera".into(),
            }])
            .unwrap();
        store
            .upsert_payment(&PaymentFacts {
                id: "PAY_REMAP".into(),
                created_at: "2027-01-15T08:00:00.000Z".into(),
                ts_ms: 1_800_000_000_000,
                updated_at: "2027-01-15T08:00:00.000Z".into(),
                updated_ts_ms: 1_800_000_000_000,
                amount: 99,
                currency: "USD".into(),
                status: "COMPLETED".into(),
                location_id: "LOC_1".into(),
                ..PaymentFacts::default()
            })
            .unwrap();
        let old = store.claim_due_thumbnail_retries(1, 100.0).unwrap();
        store
            .replace_camera_mappings(&[CameraMappingEntry {
                location_id: "LOC_1".into(),
                device_id: String::new(),
                device_name: String::new(),
                camera_id: CAMERA_B.into(),
                camera_name: "New camera".into(),
            }])
            .unwrap();
        assert!(
            !store
                .complete_thumbnail_retry(
                    "PAY_REMAP",
                    &old[0].1,
                    TEST_CAMERA_ID,
                    1_800_000_000_000,
                    "old.jpg",
                    10,
                    0,
                )
                .unwrap()
        );
        let replacement = store.claim_due_thumbnail_retries(1, 100.0).unwrap();
        assert_eq!(replacement.len(), 1);
        assert_eq!(replacement[0].0.camera_id.as_deref(), Some(CAMERA_B));
        assert_eq!(replacement[0].0.thumbnail_retry_attempts, 0);
    }

    #[test]
    fn captured_thumbnail_survives_mapping_edit_but_not_source_change() {
        const CAMERA_B: &str = "cam2bbbbbbbbbbbbbbbbbbbbb";
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        let path = add_thumbnail_asset(&store, "PAY_CAPTURED_HISTORY", 1_800_000_000_000, b"image");
        store
            .replace_camera_mappings(&[
                CameraMappingEntry {
                    location_id: "LOC_1".into(),
                    device_id: String::new(),
                    device_name: String::new(),
                    camera_id: CAMERA_B.into(),
                    camera_name: "New default".into(),
                },
                CameraMappingEntry {
                    location_id: "LOC_2".into(),
                    device_id: String::new(),
                    device_name: String::new(),
                    camera_id: CAMERA_B.into(),
                    camera_name: "Other register".into(),
                },
            ])
            .unwrap();
        let mut update = PaymentFacts {
            id: "PAY_CAPTURED_HISTORY".into(),
            created_at: "2027-01-15T08:00:00.000Z".into(),
            ts_ms: 1_800_000_000_000,
            updated_at: "2027-01-15T08:01:00.000Z".into(),
            updated_ts_ms: 1_800_000_060_000,
            amount: 99,
            currency: "USD".into(),
            status: "COMPLETED".into(),
            location_id: "LOC_1".into(),
            ..PaymentFacts::default()
        };
        store.upsert_payment(&update).unwrap();
        let preserved = store
            .get_transaction("PAY_CAPTURED_HISTORY")
            .unwrap()
            .unwrap();
        assert_eq!(preserved.camera_id.as_deref(), Some(TEST_CAMERA_ID));
        assert!(preserved.thumbnail_path.is_some());
        assert!(path.exists());

        update.location_id = "LOC_2".into();
        update.updated_at = "2027-01-15T08:02:00.000Z".into();
        update.updated_ts_ms += 60_000;
        store.upsert_payment(&update).unwrap();
        let changed = store
            .get_transaction("PAY_CAPTURED_HISTORY")
            .unwrap()
            .unwrap();
        assert_eq!(changed.camera_id.as_deref(), Some(CAMERA_B));
        assert!(changed.thumbnail_path.is_none());
        assert!(!path.exists());
    }

    #[test]
    fn vanished_thumbnail_is_cleared_and_requeued_immediately() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        let path = add_thumbnail_asset(&store, "PAY_MISSING", 1_800_000_000_000, b"image");
        fs::remove_file(path).unwrap();
        assert!(
            store
                .requeue_missing_thumbnail("PAY_MISSING", "PAY_MISSING.jpg")
                .unwrap()
        );
        assert!(
            store
                .get_transaction("PAY_MISSING")
                .unwrap()
                .unwrap()
                .thumbnail_path
                .is_none()
        );
        assert_eq!(
            store.claim_due_thumbnail_retries(10, 100.0).unwrap().len(),
            1
        );
    }

    #[test]
    fn oauth_refresh_commit_is_fenced_by_the_complete_grant_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        store
            .update_settings(
                &[
                    ("square.access_token", "old-access", true),
                    ("square.refresh_token", "old-refresh", true),
                    ("square.token_expires_at", "2027-01-15T08:00:00Z", false),
                    ("square.environment", "sandbox", false),
                    ("square.merchant_id", "MERCHANT_1", false),
                    (SQUARE_ACCOUNT_REVISION_SETTING, "revision-1", false),
                    ("square.oauth_client_id", "client-1", false),
                    ("square.oauth_client_secret", "secret-1", true),
                ],
                &[],
            )
            .unwrap();
        let stale = store.square_oauth_snapshot().unwrap();
        store
            .set_setting(SQUARE_ACCOUNT_REVISION_SETTING, "revision-2", false)
            .unwrap();
        assert!(
            !store
                .update_square_oauth_tokens(
                    &stale,
                    "discarded-access",
                    "discarded-refresh",
                    "2028-01-15T08:00:00Z",
                )
                .unwrap()
        );
        assert_eq!(
            store.get_setting("square.access_token").unwrap().as_deref(),
            Some("old-access")
        );

        let current = store.square_oauth_snapshot().unwrap();
        assert!(
            store
                .update_square_oauth_tokens(
                    &current,
                    "new-access",
                    "new-refresh",
                    "2028-01-15T08:00:00Z",
                )
                .unwrap()
        );
        assert_eq!(
            store.get_setting("square.access_token").unwrap().as_deref(),
            Some("new-access")
        );
    }

    #[test]
    fn sparse_payment_updates_preserve_device_and_expire_filtered_pages() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        let original = PaymentFacts {
            id: "PAY_FILTER".into(),
            created_at: "2027-01-15T08:00:00.000Z".into(),
            ts_ms: 1_800_000_000_000,
            updated_at: "2027-01-15T08:00:00.000Z".into(),
            updated_ts_ms: 1_800_000_000_000,
            amount: 99,
            currency: "USD".into(),
            status: "PENDING".into(),
            location_id: "LOC_1".into(),
            device_id: "DEVICE_1".into(),
            device_name: "Register One".into(),
            card_last4: "4242".into(),
            ..PaymentFacts::default()
        };
        store.upsert_payment(&original).unwrap();
        let (_, snapshot) = store
            .list_transactions_page(50, 0, None, "", "PENDING")
            .unwrap();
        let mut update = original;
        update.updated_at = "2027-01-15T08:01:00.000Z".into();
        update.updated_ts_ms += 60_000;
        update.status = "COMPLETED".into();
        update.device_id.clear();
        update.device_name.clear();
        store.upsert_payment(&update).unwrap();
        let transaction = store.get_transaction("PAY_FILTER").unwrap().unwrap();
        assert_eq!(transaction.device_id, "DEVICE_1");
        assert_eq!(transaction.device_name, "Register One");
        assert!(matches!(
            store.list_transactions_page(50, 0, Some(snapshot), "", "PENDING"),
            Err(AppError::Conflict(_))
        ));
    }

    #[test]
    fn timestamp_change_expires_unfiltered_page_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        let mut payment = PaymentFacts {
            id: "PAY_REORDER".into(),
            created_at: "2027-01-15T08:00:00.000Z".into(),
            ts_ms: 1_800_000_000_000,
            updated_at: "2027-01-15T08:00:00.000Z".into(),
            updated_ts_ms: 1_800_000_000_000,
            amount: 99,
            currency: "USD".into(),
            status: "COMPLETED".into(),
            ..PaymentFacts::default()
        };
        store.upsert_payment(&payment).unwrap();
        let (_, snapshot) = store.list_transactions_page(50, 0, None, "", "").unwrap();
        payment.ts_ms += 1_000;
        payment.updated_ts_ms += 1_000;
        payment.updated_at = "2027-01-15T08:00:01.000Z".into();
        store.upsert_payment(&payment).unwrap();
        assert!(matches!(
            store.list_transactions_page(50, 0, Some(snapshot), "", ""),
            Err(AppError::Conflict(_))
        ));
    }

    #[test]
    fn motion_alerts_preserve_delivery_and_matched_transaction_details() {
        const EVENT_TS: i64 = 1_800_000_000_000;
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        let (_, token) = store
            .configure_motion(TEST_CAMERA_ID, "Checkout Camera", 1, 0, 1, true)
            .unwrap();
        let token = token.unwrap();
        store
            .record_motion(
                &token,
                "event-1",
                EVENT_TS,
                EVENT_TS,
                "post",
                "Register motion",
                &["sensor-1".into(), "sensor-2".into()],
            )
            .unwrap();
        store
            .replace_camera_mappings(&[CameraMappingEntry {
                location_id: "LOC_1".into(),
                device_id: String::new(),
                device_name: String::new(),
                camera_id: TEST_CAMERA_ID.into(),
                camera_name: "Checkout Camera".into(),
            }])
            .unwrap();
        store
            .upsert_payment(&PaymentFacts {
                id: "PAY_MOTION".into(),
                created_at: "2027-01-15T08:00:00.500Z".into(),
                ts_ms: EVENT_TS + 500,
                updated_at: "2027-01-15T08:00:00.500Z".into(),
                updated_ts_ms: EVENT_TS + 500,
                amount: 99,
                currency: "USD".into(),
                status: "COMPLETED".into(),
                location_id: "LOC_1".into(),
                ..PaymentFacts::default()
            })
            .unwrap();

        let events = store.motion_alerts(50, true, EVENT_TS + 1_000).unwrap();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.device_identifiers, ["sensor-1", "sensor-2"]);
        assert_eq!(event.state, "matched");
        assert_eq!(event.matched_transaction_id.as_deref(), Some("PAY_MOTION"));
        assert_eq!(event.matched_transaction_ts_ms, Some(EVENT_TS + 500));
        assert_eq!(event.transaction_delta_ms, Some(500));
        let serialized = serde_json::to_value(event).unwrap();
        assert!(serialized.get("expires_at_ms").is_none());
    }

    #[test]
    fn motion_summary_counts_more_than_list_limit() {
        const EVENT_TS: i64 = 1_800_000_000_000;
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        let (_, token) = store
            .configure_motion(TEST_CAMERA_ID, "Checkout Camera", 1, 0, 1, true)
            .unwrap();
        let token = token.unwrap();
        for index in 0..300 {
            let timestamp = EVENT_TS + index * 3_000;
            store
                .record_motion(
                    &token,
                    &format!("event-{index}"),
                    timestamp,
                    timestamp,
                    "post",
                    "Register motion",
                    &[],
                )
                .unwrap();
        }

        let now = EVENT_TS + 300 * 3_000;
        assert_eq!(store.motion_alerts(250, true, now).unwrap().len(), 250);
        assert_eq!(
            store.motion_summary(now).unwrap(),
            json!({"matched": 0, "pending": 0, "flagged": 300})
        );
    }

    #[test]
    fn alarm_summaries_release_expired_claims() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        store
            .set_setting(ALARM_ENABLED_AFTER_SETTING, "0", false)
            .unwrap();
        store
            .upsert_payment(&PaymentFacts {
                id: "PAY_EXPIRED_CLAIM".into(),
                created_at: "2027-01-15T08:00:00.000Z".into(),
                ts_ms: 1_800_000_000_000,
                updated_at: "2027-01-15T08:00:00.000Z".into(),
                updated_ts_ms: 1_800_000_000_000,
                amount: 99,
                currency: "USD".into(),
                status: "COMPLETED".into(),
                ..PaymentFacts::default()
            })
            .unwrap();
        store.claim_alarm_trigger("PAY_EXPIRED_CLAIM").unwrap();
        store
            .connection()
            .unwrap()
            .execute(
                "UPDATE transactions SET alarm_claimed_at=? WHERE id='PAY_EXPIRED_CLAIM'",
                [now_seconds() - 61.0],
            )
            .unwrap();

        assert_eq!(store.queue_depths().unwrap()["alarms_pending"], 1);
        let summary = store.alarm_summary().unwrap();
        assert_eq!(summary["pending"], 1);
        assert_eq!(summary["in_progress"], 0);
    }

    #[test]
    fn webhook_lag_tracks_newest_accepted_payment_delivery() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        let first = "a".repeat(64);
        let older = "b".repeat(64);
        let newest = "c".repeat(64);
        assert!(
            store
                .record_webhook_receipt(&first, "payment.updated", 2_000, Some(1_500))
                .unwrap()
        );
        assert!(
            store
                .record_webhook_receipt(&older, "payment.created", 1_000, Some(900))
                .unwrap()
        );
        let metrics = store.webhook_metrics().unwrap();
        assert_eq!(metrics["last_payment_ms"], 2_000);
        assert_eq!(metrics["last_delivery_lag_ms"], 500);

        assert!(
            store
                .record_webhook_receipt(&newest, "payment.updated", 3_000, None)
                .unwrap()
        );
        assert!(
            !store
                .record_webhook_receipt(&newest, "payment.updated", 3_000, None)
                .unwrap()
        );
        let metrics = store.webhook_metrics().unwrap();
        assert_eq!(metrics["last_payment_ms"], 3_000);
        assert!(metrics["last_delivery_lag_ms"].is_null());
        assert_eq!(metrics["accepted_payment_count"], 3);
        assert_eq!(metrics["duplicate_count"], 1);
    }
}
