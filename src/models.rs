use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct SetupBody {
    pub password: String,
    #[serde(default)]
    pub bootstrap_secret: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginBody {
    #[serde(default = "default_admin_username")]
    pub username: String,
    pub password: String,
}

fn default_admin_username() -> String {
    "admin".into()
}

#[derive(Debug, Deserialize)]
pub struct CreateUserBody {
    pub username: String,
    pub password: String,
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetUserPasswordBody {
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct ProtectSettingsBody {
    pub host: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub verify_ssl: bool,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub alarm_trigger_id: String,
    #[serde(default)]
    pub disable_alarm: bool,
    #[serde(default)]
    pub console_switch_token: String,
}

#[derive(Debug, Deserialize)]
pub struct ProtectConsoleSwitchTokenBody {
    pub host: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub verify_ssl: bool,
}

#[derive(Debug, Deserialize)]
pub struct SquareSettingsBody {
    pub access_token: String,
    #[serde(default = "default_square_environment")]
    pub environment: String,
    #[serde(default)]
    pub webhook_signature_key: String,
    #[serde(default)]
    pub webhook_url: String,
    #[serde(default)]
    pub clear_webhook: bool,
    #[serde(default)]
    pub confirm_account_switch: bool,
    #[serde(default)]
    pub account_switch_confirmation_token: String,
}

fn default_square_environment() -> String {
    "production".into()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CameraMappingEntry {
    pub location_id: String,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub device_name: String,
    pub camera_id: String,
    #[serde(default)]
    pub camera_name: String,
}

#[derive(Debug, Deserialize)]
pub struct CameraMappingBody {
    pub mappings: Vec<CameraMappingEntry>,
}

#[derive(Debug, Deserialize)]
pub struct DiscoverProtectBody {
    #[serde(default)]
    pub host: String,
}

#[derive(Debug, Deserialize)]
pub struct SquareOAuthAppBody {
    pub client_id: String,
    pub client_secret: String,
    #[serde(default = "default_square_environment")]
    pub environment: String,
}

#[derive(Debug, Deserialize)]
pub struct DeepLinkSettingsBody {
    #[serde(default)]
    pub template: String,
}

#[derive(Debug, Deserialize)]
pub struct ThumbnailStorageSettingsBody {
    #[serde(default)]
    pub compression_enabled: bool,
    #[serde(default = "default_jpeg_quality")]
    pub jpeg_quality: i64,
    #[serde(default = "default_max_dimension")]
    pub max_dimension: i64,
    #[serde(default)]
    pub retention_days: i64,
    #[serde(default)]
    pub max_storage_mib: i64,
}

fn default_jpeg_quality() -> i64 {
    72
}

fn default_max_dimension() -> i64 {
    960
}

#[derive(Clone, Debug, Deserialize)]
pub struct TransactionQueryBody {
    #[serde(default = "default_transaction_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub snapshot: Option<i64>,
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub status: Option<String>,
}

impl Default for TransactionQueryBody {
    fn default() -> Self {
        Self {
            limit: default_transaction_limit(),
            offset: 0,
            snapshot: None,
            q: String::new(),
            status: None,
        }
    }
}

fn default_transaction_limit() -> i64 {
    50
}

#[derive(Debug, Deserialize)]
pub struct TransactionNoteBody {
    #[serde(default)]
    pub note: String,
    pub revision: i64,
}

#[derive(Debug, Deserialize)]
pub struct ProtectMotionSettingsBody {
    pub camera_id: String,
    #[serde(default = "default_match_window")]
    pub match_window_seconds: i64,
    #[serde(default = "default_motion_grace")]
    pub grace_seconds: i64,
    #[serde(default = "default_motion_retention")]
    pub retention_days: i64,
    #[serde(default)]
    pub rotate_token: bool,
}

fn default_match_window() -> i64 {
    15
}

fn default_motion_grace() -> i64 {
    90
}

fn default_motion_retention() -> i64 {
    30
}

#[derive(Clone, Debug, Serialize)]
pub struct UserRecord {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub enabled: bool,
    pub created_at: f64,
}

#[derive(Clone, Debug)]
pub struct LoginUser {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub auth_revision: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionUser {
    pub id: i64,
    pub username: String,
    pub role: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct LoginAuditRecord {
    pub id: i64,
    pub user_id: i64,
    pub username: String,
    pub role: String,
    pub client_ip: String,
    pub logged_in_at: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct TransactionRecord {
    pub id: String,
    pub created_at: String,
    pub ts_ms: i64,
    pub updated_at: String,
    pub updated_ts_ms: i64,
    pub amount: i64,
    pub currency: String,
    pub refunded_amount: i64,
    pub status: String,
    pub location_id: String,
    pub device_id: String,
    pub device_name: String,
    pub card_last4: String,
    pub receipt_url: String,
    pub camera_id: Option<String>,
    pub thumbnail_path: Option<String>,
    pub note: String,
    pub note_revision: i64,
    pub thumbnail_bytes: Option<i64>,
    pub thumbnail_policy_revision: i64,
    pub thumbnail_retired_at: Option<i64>,
    pub thumbnail_retired_reason: String,
    pub alarm_state: String,
    pub alarm_delivered_at_ms: Option<i64>,
    pub thumbnail_retry_attempts: i64,
}

#[derive(Clone, Debug, Default)]
pub struct PaymentFacts {
    pub id: String,
    pub created_at: String,
    pub ts_ms: i64,
    pub updated_at: String,
    pub updated_ts_ms: i64,
    pub amount: i64,
    pub currency: String,
    pub refunded_amount: i64,
    pub status: String,
    pub location_id: String,
    pub device_id: String,
    pub device_name: String,
    pub card_last4: String,
    pub receipt_url: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct MotionEventRecord {
    pub id: i64,
    pub camera_id: String,
    pub camera_name: String,
    pub event_ts_ms: i64,
    pub received_at_ms: i64,
    pub evaluate_after_ms: i64,
    #[serde(skip_serializing)]
    pub expires_at_ms: i64,
    pub match_window_ms: i64,
    pub delivery_method: String,
    pub alarm_name: String,
    pub device_identifiers: Vec<String>,
    pub state: String,
    pub matched_transaction_id: Option<String>,
    pub matched_transaction_ts_ms: Option<i64>,
    pub transaction_delta_ms: Option<i64>,
}
