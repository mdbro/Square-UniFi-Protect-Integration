use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, Path as AxumPath, Query, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{delete, get, post, put},
};
use chrono::DateTime;
use csv::WriterBuilder;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, RwLock};
use tower_http::{limit::RequestBodyLimitLayer, services::ServeDir};
use url::Url;

use crate::{
    AppError, AppResult, Config, Store,
    clients::{
        ProtectClient, SquareClient, oauth_authorize_url, oauth_exchange,
        validate_alarm_trigger_id, validate_protect_host, verify_square_webhook_signature,
    },
    models::*,
    security::{BootstrapSecretVerifier, hash_password, new_session_token, verify_password},
    store::{
        DEFAULT_ADMIN_USERNAME, PROTECT_CONSOLE_GENERATION_SETTING, PROTECT_CONSOLE_ID_SETTING,
        ROLE_ADMIN, SQUARE_ACCOUNT_REVISION_SETTING, now_millis, validate_camera_id,
    },
    sync::{SyncEngine, protect_from_store, run_poller, verify_protect_identity},
    thumbnail::read_thumbnail,
};

const SESSION_COOKIE: &str = "spi_session";
const LOGIN_MAX_FAILURES: usize = 5;
const LOGIN_LOCKOUT_SECONDS: u64 = 60;
const LOGIN_FAILURE_KEY_LIMIT: usize = 10_000;
const DUMMY_PASSWORD_HASH: &str = concat!(
    "scrypt$00000000000000000000000000000000$",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000"
);
const DEFAULT_DEEP_LINK_TEMPLATE: &str =
    "https://{host}/protect/timelapse/{camera_id}?start={ts_ms}";

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub config: Config,
    pub sync: SyncEngine,
    bootstrap: Arc<BootstrapSecretVerifier>,
    login_failures: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    maintenance: Arc<RwLock<Value>>,
    maintenance_queue: Arc<Mutex<MaintenanceQueue>>,
}

#[derive(Default)]
struct MaintenanceQueue {
    active: bool,
    pending: bool,
    optimize_requested: bool,
}

impl AppState {
    pub fn new(store: Store, config: Config) -> Self {
        let setup_complete = store.setup_complete().unwrap_or(false);
        let supplied = config.bootstrap_secret.clone();
        let bootstrap = BootstrapSecretVerifier::new(supplied, !setup_complete);
        Self {
            sync: SyncEngine::new(store.clone()),
            store,
            config,
            bootstrap: Arc::new(bootstrap),
            login_failures: Arc::new(Mutex::new(HashMap::new())),
            maintenance: Arc::new(RwLock::new(json!({"state": "idle", "result": null}))),
            maintenance_queue: Arc::new(Mutex::new(MaintenanceQueue::default())),
        }
    }

    pub fn start_background_work(&self) {
        if let Some(interval) = self.config.poll_interval {
            tokio::spawn(run_poller(self.sync.clone(), interval));
        }
        let state = self.clone();
        tokio::spawn(async move {
            state
                .run_maintenance_scheduler(Duration::from_secs(60))
                .await;
        });
    }

    async fn run_maintenance_scheduler(self, retry_interval: Duration) {
        self.schedule_maintenance(false).await;
        let mut timer = tokio::time::interval(retry_interval);
        timer.tick().await;
        loop {
            timer.tick().await;
            match self.store.orphan_thumbnail_cleanup_pending() {
                Ok(true) => {
                    self.schedule_maintenance(false).await;
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(%error, "could not check pending thumbnail cleanup");
                }
            }
        }
    }

    async fn schedule_maintenance(&self, optimize_existing: bool) -> bool {
        let mut queue = self.maintenance_queue.lock().await;
        queue.optimize_requested |= optimize_existing;
        if queue.active {
            queue.pending = true;
            return false;
        }
        queue.active = true;
        queue.pending = false;
        *self.maintenance.write().await = json!({
            "state": "queued",
            "started_at_ms": null,
            "completed_at_ms": null,
            "optimize_existing": optimize_existing,
            "result": null,
            "error": "",
        });
        drop(queue);
        let state = self.clone();
        tokio::spawn(async move { state.run_maintenance_queue().await });
        true
    }

    async fn run_maintenance_queue(self) {
        loop {
            let optimize_existing = {
                let mut queue = self.maintenance_queue.lock().await;
                let optimize = queue.optimize_requested;
                queue.optimize_requested = false;
                queue.pending = false;
                optimize
            };
            let started_at_ms = now_millis();
            *self.maintenance.write().await = json!({
                "state": "running",
                "started_at_ms": started_at_ms,
                "completed_at_ms": null,
                "optimize_existing": optimize_existing,
                "result": null,
                "error": "",
            });
            let store = self.store.clone();
            let result = tokio::task::spawn_blocking(move || {
                store.run_thumbnail_maintenance(optimize_existing, now_millis())
            })
            .await;
            let completed_at_ms = now_millis();
            *self.maintenance.write().await = match result {
                Ok(Ok(result)) => json!({
                    "state": "complete",
                    "started_at_ms": started_at_ms,
                    "completed_at_ms": completed_at_ms,
                    "optimize_existing": optimize_existing,
                    "result": result,
                    "error": "",
                }),
                Ok(Err(error)) => {
                    tracing::error!(%error, "thumbnail maintenance failed");
                    json!({
                        "state": "error",
                        "started_at_ms": started_at_ms,
                        "completed_at_ms": completed_at_ms,
                        "optimize_existing": optimize_existing,
                        "result": null,
                        "error": "Thumbnail maintenance failed; see the server log",
                    })
                }
                Err(error) => {
                    tracing::error!(%error, "thumbnail maintenance task failed");
                    json!({
                        "state": "error",
                        "started_at_ms": started_at_ms,
                        "completed_at_ms": completed_at_ms,
                        "optimize_existing": optimize_existing,
                        "result": null,
                        "error": "Thumbnail maintenance failed; see the server log",
                    })
                }
            };
            let mut queue = self.maintenance_queue.lock().await;
            if queue.pending || queue.optimize_requested {
                continue;
            }
            queue.active = false;
            break;
        }
    }
}

pub fn build_router(state: AppState) -> Router {
    let static_service =
        ServeDir::new(&state.config.static_dir).append_index_html_on_directories(true);
    Router::new()
        .route("/api/status", get(status))
        .route("/api/setup", post(setup))
        .route("/api/login", post(login))
        .route("/api/session", get(session))
        .route("/api/logout", post(logout))
        .route("/api/users", get(users).post(create_user))
        .route("/api/users/{user_id}/password", put(reset_user_password))
        .route("/api/login-audit", get(login_audit))
        .route(
            "/api/settings/protect/alarm",
            get(protect_alarm_settings).delete(delete_protect_alarm),
        )
        .route("/api/settings/protect/alarm/test", post(test_protect_alarm))
        .route("/api/discover/protect", post(discover_protect))
        .route(
            "/api/settings/protect/console-switch-token",
            post(protect_switch_token),
        )
        .route("/api/settings/protect", put(set_protect))
        .route("/api/settings/square", put(set_square))
        .route(
            "/api/settings/deep-link",
            get(get_deep_link).put(set_deep_link),
        )
        .route(
            "/api/settings/protect/motion-webhook",
            get(get_motion_settings)
                .put(set_motion_settings)
                .delete(delete_motion_settings),
        )
        .route(
            "/api/settings/thumbnail-storage",
            get(get_thumbnail_settings).put(set_thumbnail_settings),
        )
        .route(
            "/api/settings/thumbnail-storage/maintenance",
            post(run_thumbnail_maintenance),
        )
        .route(
            "/api/settings/square/webhook/register",
            post(square_webhook_registration_disabled),
        )
        .route(
            "/api/settings/square/oauth-app",
            get(get_square_oauth_app).put(set_square_oauth_app),
        )
        .route("/oauth/square/start", get(square_oauth_start))
        .route("/oauth/square/callback", get(square_oauth_callback))
        .route(
            "/api/settings/square/oauth-switch/confirm",
            post(confirm_oauth_switch),
        )
        .route(
            "/api/settings/square/oauth-switch",
            delete(cancel_oauth_switch),
        )
        .route("/api/health/protect", get(protect_health))
        .route("/api/cameras", get(cameras))
        .route("/api/health/square", get(square_health))
        .route("/api/locations", get(locations))
        .route("/api/pos-devices", get(pos_devices))
        .route("/api/camera-preview/{camera_id}", get(camera_preview))
        .route("/api/camera-mapping", get(get_mapping).put(set_mapping))
        .route("/api/dashboard", get(dashboard))
        .route("/api/motion-alerts", get(motion_alerts))
        .route("/api/transactions/export.csv", get(export_transactions))
        .route(
            "/api/transactions",
            get(get_transactions).post(post_transactions),
        )
        .route(
            "/api/transactions/{transaction_id}/note",
            put(set_transaction_note),
        )
        .route("/api/thumbnails/{transaction_id}", get(thumbnail))
        .route("/api/sync", post(manual_sync))
        .route(
            "/webhooks/protect/motion",
            get(protect_motion_get).post(protect_motion_post),
        )
        .route("/webhooks/square", post(square_webhook))
        .fallback_service(static_service)
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn security_headers(request: Request, next: Next) -> Response {
    let api_request = request.uri().path().starts_with("/api/")
        || request.uri().path().starts_with("/webhooks/")
        || request.uri().path().starts_with("/oauth/");
    let mut response = next.run(request).await;
    for (name, value) in [
        (
            "content-security-policy",
            "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self'; object-src 'none'; script-src 'self'; style-src 'self'",
        ),
        ("cross-origin-resource-policy", "same-origin"),
        (
            "permissions-policy",
            "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
        ),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("x-permitted-cross-domain-policies", "none"),
    ] {
        response.headers_mut().insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    if !response.headers().contains_key(header::CACHE_CONTROL) {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(if api_request {
                "private, no-store"
            } else {
                // HTML and scripts must revalidate together after an upgrade.
                // Heuristic caching can otherwise run an old script against a
                // new page and crash before any application view is visible.
                "no-cache"
            }),
        );
    }
    response
}

async fn status(State(state): State<AppState>) -> AppResult<Response> {
    Ok(json_response(json!({
        "setup_complete": state.store.setup_complete()?,
        "protect_configured": state.store.get_setting("protect.host")?.is_some(),
        "square_configured": state.store.get_setting("square.access_token")?.is_some(),
        "cameras_mapped": !state.store.get_camera_mappings()?.is_empty(),
        "backend": "rust",
    })))
}

async fn setup(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(mut body): Json<SetupBody>,
) -> AppResult<Response> {
    validate_password(&body.password)?;
    if body.bootstrap_secret.len() > 4096 {
        body.bootstrap_secret.clear();
        return Err(AppError::Unprocessable(
            "Bootstrap secret is too long".into(),
        ));
    }
    if state.store.setup_complete()? {
        state.bootstrap.clear();
        return Err(AppError::Conflict("Setup already completed".into()));
    }
    if !state.config.tls_enabled && !explicit_loopback_request(&state.config, peer, &headers) {
        body.bootstrap_secret.clear();
        return Err(AppError::Structured(
            StatusCode::FORBIDDEN,
            json!({"detail": {
                "code": "bootstrap_tls_not_configured",
                "message": "Non-local first-run setup requires the app's built-in TLS. Set SPI_TLS=1 and restart before opening the remote setup page. Forwarded request headers cannot satisfy this requirement."
            }}),
        ));
    }
    let valid = state.bootstrap.verify(&body.bootstrap_secret);
    body.bootstrap_secret.clear();
    if !valid {
        return Err(AppError::Structured(
            StatusCode::FORBIDDEN,
            json!({"detail": {
                "code": "invalid_bootstrap_secret",
                "message": "First-run setup requires the one-time bootstrap secret configured in SPI_BOOTSTRAP_SECRET or printed in the server console at startup."
            }}),
        ));
    }
    let password = std::mem::take(&mut body.password);
    let hash = hash_password_async(password).await?;
    if !state.store.create_initial_admin(&hash)? {
        state.bootstrap.clear();
        return Err(AppError::Conflict("Setup already completed".into()));
    }
    state.bootstrap.clear();
    Ok(json_response(
        json!({"ok": true, "username": DEFAULT_ADMIN_USERNAME}),
    ))
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<LoginBody>,
) -> AppResult<Response> {
    if body.password.len() > 256 || body.username.len() > 64 {
        return Err(AppError::Unauthorized(
            "Invalid username or password".into(),
        ));
    }
    if !state.store.setup_complete()? {
        return Err(AppError::Conflict("Run setup first".into()));
    }
    let throttle_key = peer.ip().to_string();
    {
        let mut failures = state.login_failures.lock().await;
        prune_login_failures(&mut failures);
        let attempts = failures.get(&throttle_key);
        if (attempts.is_none() && failures.len() >= LOGIN_FAILURE_KEY_LIMIT)
            || attempts.is_some_and(|attempts| attempts.len() >= LOGIN_MAX_FAILURES)
        {
            return Err(AppError::Structured(
                StatusCode::TOO_MANY_REQUESTS,
                json!({"detail": "Too many login attempts; try again in a minute"}),
            ));
        }
    }
    let account = state.store.user_for_login(&body.username)?;
    let stored = account
        .as_ref()
        .map(|value| value.password_hash.as_str())
        .unwrap_or(DUMMY_PASSWORD_HASH)
        .to_owned();
    let password = body.password;
    let password_valid = tokio::task::spawn_blocking(move || verify_password(&password, &stored))
        .await
        .map_err(AppError::internal)?;
    if account.is_none() || !password_valid {
        let mut failures = state.login_failures.lock().await;
        prune_login_failures(&mut failures);
        if !failures.contains_key(&throttle_key) && failures.len() >= LOGIN_FAILURE_KEY_LIMIT {
            return Err(AppError::Structured(
                StatusCode::TOO_MANY_REQUESTS,
                json!({"detail": "Too many login attempts; try again in a minute"}),
            ));
        }
        let attempts = failures.entry(throttle_key).or_default();
        if attempts.len() >= LOGIN_MAX_FAILURES {
            return Err(AppError::Structured(
                StatusCode::TOO_MANY_REQUESTS,
                json!({"detail": "Too many login attempts; try again in a minute"}),
            ));
        }
        attempts.push(Instant::now());
        return Err(AppError::Unauthorized(
            "Invalid username or password".into(),
        ));
    }
    let account = account.expect("checked above");
    let token = new_session_token();
    let user = state.store.create_session(
        &token,
        account.id,
        account.auth_revision,
        &peer.ip().to_string(),
    )?;
    state.login_failures.lock().await.remove(&throttle_key);
    let mut response = json_response(json!({
        "ok": true,
        "user": {"username": user.username, "role": user.role},
    }));
    response.headers_mut().append(
        header::SET_COOKIE,
        session_cookie(&token, state.config.cookie_secure)?,
    );
    Ok(response)
}

fn prune_login_failures(failures: &mut HashMap<String, Vec<Instant>>) {
    failures.retain(|_, attempts| {
        attempts.retain(|time| time.elapsed() < Duration::from_secs(LOGIN_LOCKOUT_SECONDS));
        !attempts.is_empty()
    });
}

async fn session(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
    let user = require_session(&state, &headers)?;
    Ok(json_response(json!({
        "user": {"username": user.username, "role": user.role}
    })))
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
    require_session(&state, &headers)?;
    if let Some(token) = session_token(&headers) {
        state.store.delete_session(&token)?;
    }
    let mut response = json_response(json!({"ok": true}));
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static("spi_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"),
    );
    Ok(response)
}

async fn users(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
    let current = require_admin(&state, &headers)?;
    let users = state
        .store
        .list_users()?
        .into_iter()
        .map(|user| {
            let current_user = user.id == current.id;
            let mut value = serde_json::to_value(user).expect("serializable user");
            value["current"] = Value::Bool(current_user);
            value
        })
        .collect::<Vec<_>>();
    Ok(json_response(json!({"users": users})))
}

async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateUserBody>,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    validate_password(&body.password)?;
    let hash = hash_password_async(body.password).await?;
    let user = state.store.create_user(&body.username, &hash, &body.role)?;
    let mut value = serde_json::to_value(user).map_err(AppError::internal)?;
    value["current"] = Value::Bool(false);
    Ok((
        StatusCode::CREATED,
        Json(json!({"ok": true, "user": value})),
    )
        .into_response())
}

async fn reset_user_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(user_id): AxumPath<i64>,
    Json(body): Json<ResetUserPasswordBody>,
) -> AppResult<Response> {
    let current = require_admin(&state, &headers)?;
    validate_password(&body.password)?;
    let hash = hash_password_async(body.password).await?;
    let Some((user, revoked)) = state.store.reset_user_password(user_id, &hash)? else {
        return Err(AppError::NotFound("User not found".into()));
    };
    Ok(json_response(json!({
        "ok": true,
        "user": user,
        "sessions_revoked": revoked,
        "current_session_revoked": user_id == current.id,
    })))
}

#[derive(Deserialize)]
struct AuditQuery {
    #[serde(default = "default_audit_limit")]
    limit: i64,
    before_id: Option<i64>,
}

fn default_audit_limit() -> i64 {
    100
}

async fn login_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let (events, next) = state.store.list_login_audit(query.limit, query.before_id)?;
    Ok(json_response(
        json!({"events": events, "next_before_id": next}),
    ))
}

async fn protect_alarm_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    alarm_settings_response(&state, None)
}

fn alarm_settings_response(state: &AppState, accepted: Option<i64>) -> AppResult<Response> {
    let mut value = state.store.alarm_summary()?;
    if let Some(accepted) = accepted {
        value["test_accepted_at_ms"] = json!(accepted);
    }
    let mut response = json_response(value);
    response.headers_mut().insert(
        HeaderName::from_static("x-protect-console-generation"),
        HeaderValue::from_str(
            &state
                .store
                .get_setting(PROTECT_CONSOLE_GENERATION_SETTING)?
                .unwrap_or_default(),
        )
        .map_err(AppError::internal)?,
    );
    Ok(response)
}

async fn test_protect_alarm(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let _provider_guard = state.store.integration_guard(false)?;
    let protect = protect_from_store(&state.store)?
        .ok_or_else(|| AppError::Conflict("UniFi Protect is not configured".into()))?;
    let trigger = state
        .store
        .get_setting("protect.alarm_trigger_id")?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::Conflict("Protect transaction flags are not configured".into()))?;
    let (_, observed) = protect.cameras_with_console_identity().await?;
    verify_protect_identity(&state.store, observed.as_deref())?;
    protect.trigger_alarm(&trigger).await?;
    alarm_settings_response(&state, Some(now_millis()))
}

async fn delete_protect_alarm(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let _provider_guard = state.store.integration_guard(true)?;
    state.store.delete_settings(&[
        "protect.api_key",
        "protect.alarm_trigger_id",
        "protect.alarm_enabled_after_ms",
    ])?;
    state.store.suppress_pending_alarms()?;
    Ok(json_response(
        json!({"ok": true, "alarm_configured": false}),
    ))
}

async fn discover_protect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DiscoverProtectBody>,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let host = if body.host.trim().is_empty() {
        None
    } else {
        Some(
            validate_protect_host(&body.host)?
                .split(':')
                .next()
                .unwrap_or("")
                .to_owned(),
        )
    };
    let devices = tokio::task::spawn_blocking(move || discover_unifi(host.as_deref()))
        .await
        .map_err(AppError::internal)??;
    Ok(json_response(Value::Array(devices)))
}

async fn protect_switch_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ProtectConsoleSwitchTokenBody>,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let _provider_guard = state.store.integration_guard(true)?;
    let host = validate_protect_host(&body.host)?;
    let client = ProtectClient::new(&host, &body.username, &body.password, body.verify_ssl, None)?;
    let (_, console_id) = client.cameras_with_console_identity().await?;
    let token = new_session_token();
    state.store.update_settings(
        &[
            ("protect.switch_token", &token, true),
            ("protect.switch_host", &host, false),
            (
                "protect.switch_console_id",
                console_id.as_deref().unwrap_or(""),
                false,
            ),
            (
                "protect.switch_expires_at",
                &(now_millis() + 300_000).to_string(),
                false,
            ),
        ],
        &[],
    )?;
    Ok(json_response(json!({"token": token})))
}

async fn set_protect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ProtectSettingsBody>,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    if body.api_key.len() > 512 || body.console_switch_token.len() > 2048 {
        return Err(AppError::Unprocessable(
            "Invalid Protect settings payload".into(),
        ));
    }
    if body.disable_alarm {
        let _provider_guard = state.store.integration_guard(true)?;
        state.store.delete_settings(&[
            "protect.api_key",
            "protect.alarm_trigger_id",
            "protect.alarm_enabled_after_ms",
        ])?;
        state.store.suppress_pending_alarms()?;
        return Ok(json_response(json!({
            "ok": true, "alarm_configured": false, "cameras": null
        })));
    }
    let host = validate_protect_host(&body.host)?;
    let submitted_trigger = if body.alarm_trigger_id.trim().is_empty() {
        None
    } else {
        Some(validate_alarm_trigger_id(&body.alarm_trigger_id)?)
    };
    let existing_host = state.store.get_setting("protect.host")?;
    let existing_generation = state
        .store
        .get_setting(PROTECT_CONSOLE_GENERATION_SETTING)?;
    let prior_console_id = state.store.get_setting(PROTECT_CONSOLE_ID_SETTING)?;
    let stored_api_key = state.store.get_setting("protect.api_key")?;
    let stored_trigger = state.store.get_setting("protect.alarm_trigger_id")?;
    let stored_alarm_boundary = state.store.get_setting("protect.alarm_enabled_after_ms")?;
    let host_changed = existing_host.as_deref().is_some_and(|old| old != host);
    if host_changed && body.console_switch_token.is_empty() {
        return Err(AppError::Conflict(
            "Protect host changed. Confirm the console switch to clear old camera mappings and Protect evidence, then save again.".into(),
        ));
    }
    let submitted_api_key =
        (!body.api_key.trim().is_empty()).then(|| body.api_key.trim().to_owned());
    let candidate_api_key = submitted_api_key
        .clone()
        .or_else(|| (!host_changed).then(|| stored_api_key.clone()).flatten());
    let client = ProtectClient::new(
        &host,
        &body.username,
        &body.password,
        body.verify_ssl,
        candidate_api_key.as_deref(),
    )?;
    let (cameras, console_id) = client.cameras_with_console_identity().await?;
    let identity_changed =
        existing_host.is_some() && prior_console_id.is_some() && prior_console_id != console_id;
    let switched = host_changed || identity_changed;
    if switched
        && !valid_protect_switch_token(
            &state,
            &body.console_switch_token,
            &host,
            console_id.as_deref(),
        )?
    {
        return Err(AppError::Conflict(
            "Protect console identity changed. Confirm the console switch, then save again.".into(),
        ));
    }
    let api_key =
        submitted_api_key.or_else(|| (!switched).then(|| stored_api_key.clone()).flatten());
    let trigger =
        submitted_trigger.or_else(|| (!switched).then(|| stored_trigger.clone()).flatten());
    if trigger.is_some() && api_key.is_none() {
        return Err(AppError::Unprocessable(
            "Protect API key is required when an alarm trigger id is set".into(),
        ));
    }
    if api_key.is_some() {
        client.integration_info().await?;
    }

    let _provider_guard = state.store.integration_guard(true)?;
    if state.store.get_setting("protect.host")? != existing_host
        || state
            .store
            .get_setting(PROTECT_CONSOLE_GENERATION_SETTING)?
            != existing_generation
        || state.store.get_setting(PROTECT_CONSOLE_ID_SETTING)? != prior_console_id
        || state.store.get_setting("protect.api_key")? != stored_api_key
        || state.store.get_setting("protect.alarm_trigger_id")? != stored_trigger
        || state.store.get_setting("protect.alarm_enabled_after_ms")? != stored_alarm_boundary
    {
        return Err(AppError::Conflict(
            "Protect settings changed while credentials were being verified; review and save again"
                .into(),
        ));
    }
    if switched
        && !valid_protect_switch_token(
            &state,
            &body.console_switch_token,
            &host,
            console_id.as_deref(),
        )?
    {
        return Err(AppError::Conflict(
            "Protect console switch confirmation expired; confirm the target again".into(),
        ));
    }
    if switched {
        state.store.clear_protect_evidence_under_guard()?;
    }
    let generation = if switched || existing_generation.is_none() {
        new_session_token()
    } else {
        existing_generation.unwrap_or_default()
    };
    let verify_ssl = if body.verify_ssl { "1" } else { "0" };
    let mut owned = vec![
        ("protect.host", host.clone(), false),
        ("protect.username", body.username.clone(), false),
        ("protect.password", body.password.clone(), true),
        ("protect.verify_ssl", verify_ssl.into(), false),
        (PROTECT_CONSOLE_GENERATION_SETTING, generation, false),
    ];
    if let Some(console_id) = console_id.as_ref() {
        owned.push((PROTECT_CONSOLE_ID_SETTING, console_id.clone(), false));
    }
    if let Some(value) = api_key.as_ref() {
        owned.push(("protect.api_key", value.clone(), true));
    }
    if let Some(value) = trigger.as_ref() {
        owned.push(("protect.alarm_trigger_id", value.clone(), false));
    }
    let alarm_activated = api_key.is_some()
        && trigger.is_some()
        && (switched
            || stored_api_key.is_none()
            || stored_trigger.is_none()
            || stored_alarm_boundary.is_none());
    if alarm_activated {
        owned.push((
            "protect.alarm_enabled_after_ms",
            now_millis().to_string(),
            false,
        ));
    }
    let updates: Vec<_> = owned
        .iter()
        .map(|(key, value, secret)| (*key, value.as_str(), *secret))
        .collect();
    let mut deletes = vec![
        "protect.switch_token",
        "protect.switch_host",
        "protect.switch_console_id",
        "protect.switch_expires_at",
    ];
    if console_id.is_none() {
        deletes.push(PROTECT_CONSOLE_ID_SETTING);
    }
    if switched && api_key.is_none() {
        deletes.push("protect.api_key");
    }
    if switched && trigger.is_none() {
        deletes.push("protect.alarm_trigger_id");
    }
    if switched && !alarm_activated {
        deletes.push("protect.alarm_enabled_after_ms");
    }
    state.store.update_settings(&updates, &deletes)?;
    if alarm_activated {
        state.store.suppress_pending_alarms()?;
    }
    Ok(json_response(json!({
        "ok": true,
        "cameras": cameras.len(),
        "alarm_configured": api_key.is_some() && trigger.is_some(),
        "console_switched": switched,
    })))
}

fn valid_protect_switch_token(
    state: &AppState,
    presented: &str,
    host: &str,
    console_id: Option<&str>,
) -> AppResult<bool> {
    let stored = state
        .store
        .get_setting("protect.switch_token")?
        .unwrap_or_default();
    let stored_host = state
        .store
        .get_setting("protect.switch_host")?
        .unwrap_or_default();
    let stored_console_id = state
        .store
        .get_setting("protect.switch_console_id")?
        .unwrap_or_default();
    let expiry = state
        .store
        .get_setting("protect.switch_expires_at")?
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0);
    Ok(!presented.is_empty()
        && stored.len() == presented.len()
        && bool::from(stored.as_bytes().ct_eq(presented.as_bytes()))
        && stored_host == host
        && stored_console_id == console_id.unwrap_or("")
        && expiry >= now_millis())
}

async fn set_square(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SquareSettingsBody>,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    if body.account_switch_confirmation_token.len() > 4096 {
        return Err(AppError::Unprocessable(
            "Invalid Square account switch confirmation".into(),
        ));
    }
    if !matches!(body.environment.as_str(), "production" | "sandbox") {
        return Err(AppError::Unprocessable("Invalid environment".into()));
    }
    if body.webhook_signature_key.is_empty() != body.webhook_url.is_empty() {
        return Err(AppError::Unprocessable(
            "Webhook signature key and notification URL must be provided together".into(),
        ));
    }
    if !body.webhook_url.is_empty() {
        validate_https_url(&body.webhook_url)?;
    }
    let square = SquareClient::new(&body.access_token, &body.environment)?;
    let locations = square.list_locations().await?;
    let merchant_id = square.merchant_id().await?;
    square.payment_page(None, None, None, 1).await?;
    save_verified_square_account(&state, body, locations, merchant_id)
}

fn square_account_changed(
    state: &AppState,
    merchant_id: &str,
    environment: &str,
) -> AppResult<bool> {
    let old = state
        .store
        .get_settings(["square.merchant_id", "square.environment"])?;
    Ok(old["square.merchant_id"]
        .as_deref()
        .is_some_and(|value| !value.is_empty() && value != merchant_id)
        || old["square.environment"]
            .as_deref()
            .is_some_and(|value| value != environment))
}

fn save_verified_square_account(
    state: &AppState,
    body: SquareSettingsBody,
    locations: Vec<Value>,
    merchant_id: String,
) -> AppResult<Response> {
    let _provider_guard = state.store.integration_guard(true)?;
    let switched = square_account_changed(state, &merchant_id, &body.environment)?;
    if switched && !body.confirm_account_switch {
        let token = new_session_token();
        state.store.update_settings(
            &[
                ("square.switch_token", &token, true),
                ("square.switch_merchant", &merchant_id, false),
                ("square.switch_environment", &body.environment, false),
                (
                    "square.switch_expires_at",
                    &(now_millis() + 300_000).to_string(),
                    false,
                ),
            ],
            &[],
        )?;
        return Err(AppError::Structured(
            StatusCode::CONFLICT,
            json!({"detail": {
                "code": "square_account_switch_confirmation_required",
                "message": "These credentials belong to a different Square account or environment. Confirm the account switch to erase the previous account's local transactions, thumbnails, POS devices, camera mappings, sync history, and saved Square webhook credentials.",
                "confirmation_token": token,
            }}),
        ));
    }
    if switched {
        let stored = state
            .store
            .get_setting("square.switch_token")?
            .unwrap_or_default();
        let target = state
            .store
            .get_setting("square.switch_merchant")?
            .unwrap_or_default();
        let expiry = state
            .store
            .get_setting("square.switch_expires_at")?
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0);
        let target_environment = state.store.get_setting("square.switch_environment")?;
        let presented = body.account_switch_confirmation_token.as_bytes();
        let stored_token = stored.as_bytes();
        let token_matches =
            stored_token.len() == presented.len() && bool::from(stored_token.ct_eq(presented));
        if !token_matches
            || target != merchant_id
            || target_environment.as_deref() != Some(body.environment.as_str())
            || expiry < now_millis()
        {
            return Err(AppError::Conflict(
                "Square account switch confirmation expired; reconnect and confirm again".into(),
            ));
        }
    }
    let revision = new_session_token();
    let mut owned = vec![
        ("square.access_token", body.access_token.clone(), true),
        ("square.environment", body.environment.clone(), false),
        ("square.merchant_id", merchant_id, false),
        (SQUARE_ACCOUNT_REVISION_SETTING, revision.clone(), false),
    ];
    let delete_webhook = body.clear_webhook || switched;
    if !body.webhook_signature_key.is_empty() {
        owned.push((
            "square.webhook_signature_key",
            body.webhook_signature_key.clone(),
            true,
        ));
        owned.push(("square.webhook_url", body.webhook_url.clone(), false));
    }
    let updates: Vec<_> = owned
        .iter()
        .map(|(key, value, secret)| (*key, value.as_str(), *secret))
        .collect();
    let mut deletes = vec![
        "square.switch_token",
        "square.switch_merchant",
        "square.switch_environment",
        "square.switch_expires_at",
        "square.refresh_token",
        "square.token_expires_at",
    ];
    deletes.extend(oauth_pending_keys());
    if delete_webhook && body.webhook_signature_key.is_empty() {
        deletes.extend(["square.webhook_signature_key", "square.webhook_url"]);
    }
    if delete_webhook || !body.webhook_signature_key.is_empty() {
        deletes.push("square.webhook_subscription_id");
    }
    let webhook_configured = !body.webhook_signature_key.is_empty()
        || (!delete_webhook
            && state
                .store
                .get_setting("square.webhook_signature_key")?
                .is_some_and(|value| !value.is_empty()));
    let evidence_cleanup_pending = state
        .store
        .save_square_account_under_guard(&updates, &deletes, switched)?;
    Ok(json_response(json!({
        "ok": true,
        "locations": locations,
        "account_switched": switched,
        "webhook_configured": webhook_configured,
        "account_revision": revision,
        "evidence_cleanup_pending": evidence_cleanup_pending,
    })))
}

async fn get_deep_link(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    Ok(json_response(deep_link_settings(&state)?))
}

async fn set_deep_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DeepLinkSettingsBody>,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let template = body.template.trim();
    if template.is_empty() || template == DEFAULT_DEEP_LINK_TEMPLATE {
        state.store.delete_settings(&["deep_link_template"])?;
    } else {
        validate_deep_link_template(template)?;
        state
            .store
            .set_setting("deep_link_template", template, false)?;
    }
    let mut value = deep_link_settings(&state)?;
    value["ok"] = Value::Bool(true);
    Ok(json_response(value))
}

fn deep_link_settings(state: &AppState) -> AppResult<Value> {
    Ok(json!({
        "template": state.store.get_setting("deep_link_template")?.unwrap_or_default(),
        "default_template": DEFAULT_DEEP_LINK_TEMPLATE,
    }))
}

async fn get_motion_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    motion_settings_response(&state, None)
}

fn motion_settings_response(state: &AppState, token: Option<String>) -> AppResult<Response> {
    let value = motion_settings_value(state, token)?;
    let mut response = json_response(value);
    add_protect_generation_header(state, &mut response)?;
    Ok(response)
}

fn motion_settings_value(state: &AppState, token: Option<String>) -> AppResult<Value> {
    let mut value = state.store.motion_config()?.to_json();
    value["webhook_path"] = Value::String("/webhooks/protect/motion".into());
    value["webhook_header"] = Value::String("X-SPI-Webhook-Token".into());
    if let Some(token) = token {
        value["webhook_token"] = Value::String(token);
    }
    Ok(value)
}

fn add_protect_generation_header(state: &AppState, response: &mut Response) -> AppResult<()> {
    response.headers_mut().insert(
        HeaderName::from_static("x-protect-console-generation"),
        HeaderValue::from_str(
            &state
                .store
                .get_setting(PROTECT_CONSOLE_GENERATION_SETTING)?
                .unwrap_or_default(),
        )
        .map_err(AppError::internal)?,
    );
    Ok(())
}

async fn set_motion_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ProtectMotionSettingsBody>,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let _provider_guard = state.store.integration_guard(false)?;
    validate_camera_id(&body.camera_id)?;
    let protect = protect_from_store(&state.store)?
        .ok_or_else(|| AppError::Conflict("UniFi Protect is not configured".into()))?;
    let (cameras, observed) = protect.cameras_with_console_identity().await?;
    verify_protect_identity(&state.store, observed.as_deref())?;
    let camera = cameras
        .iter()
        .find(|value| value.get("id").and_then(Value::as_str) == Some(&body.camera_id))
        .ok_or_else(|| {
            AppError::Unprocessable(
                "Motion alert camera was not found on this Protect console".into(),
            )
        })?;
    let name = camera.get("name").and_then(Value::as_str).unwrap_or("");
    let (_, token) = state.store.configure_motion(
        &body.camera_id,
        name,
        body.match_window_seconds,
        body.grace_seconds,
        body.retention_days,
        body.rotate_token,
    )?;
    motion_settings_response(&state, token)
}

async fn delete_motion_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let _provider_guard = state.store.integration_guard(false)?;
    state.store.disable_motion()?;
    let mut value = motion_settings_value(&state, None)?;
    value["ok"] = Value::Bool(true);
    let mut response = json_response(value);
    add_protect_generation_header(&state, &mut response)?;
    Ok(response)
}

async fn get_thumbnail_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    thumbnail_settings_response(&state).await
}

async fn set_thumbnail_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ThumbnailStorageSettingsBody>,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    state.store.update_thumbnail_policy(
        body.compression_enabled,
        body.jpeg_quality,
        body.max_dimension,
        body.retention_days,
        body.max_storage_mib,
    )?;
    state
        .schedule_maintenance(body.compression_enabled && body.max_storage_mib > 0)
        .await;
    let mut value = thumbnail_settings_value(&state).await?;
    value["ok"] = Value::Bool(true);
    Ok(json_response(value))
}

async fn run_thumbnail_maintenance(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    state.schedule_maintenance(true).await;
    let mut value = thumbnail_settings_value(&state).await?;
    value["ok"] = Value::Bool(true);
    Ok(json_response(value))
}

async fn thumbnail_settings_response(state: &AppState) -> AppResult<Response> {
    Ok(json_response(thumbnail_settings_value(state).await?))
}

async fn thumbnail_settings_value(state: &AppState) -> AppResult<Value> {
    Ok(json!({
        "compression_enabled": state.store.get_setting("thumbnail.compression_enabled")?.as_deref() == Some("1"),
        "jpeg_quality": integer_setting(&state.store, "thumbnail.jpeg_quality", 72),
        "max_dimension": integer_setting(&state.store, "thumbnail.max_dimension", 960),
        "retention_days": integer_setting(&state.store, "thumbnail.retention_days", 0),
        "max_storage_mib": integer_setting(&state.store, "thumbnail.max_storage_mib", 0),
        "policy_revision": integer_setting(&state.store, "thumbnail.policy_revision", 0),
        "usage": state.store.thumbnail_summary()?,
        "maintenance": state.maintenance.read().await.clone(),
    }))
}

async fn square_webhook_registration_disabled(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    Err(AppError::Forbidden(
        "Square access is read-only. Configure webhook subscriptions in the Square Developer Console, then save the signature key and notification URL locally.".into(),
    ))
}

async fn get_square_oauth_app(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let _provider_guard = state.store.integration_guard(false)?;
    Ok(json_response(square_oauth_app_value(&state)?))
}

fn square_oauth_app_value(state: &AppState) -> AppResult<Value> {
    let snapshot = state.store.square_oauth_snapshot()?;
    let present = |value: &Option<String>| value.as_ref().is_some_and(|s| !s.is_empty());
    let configured = present(&snapshot.client_id) && present(&snapshot.client_secret);
    let active = present(&snapshot.access_token);
    let pending_access = state
        .store
        .get_setting("square.oauth_pending_access_token")?
        .unwrap_or_default();
    let pending_merchant = state
        .store
        .get_setting("square.oauth_pending_merchant_id")?
        .unwrap_or_default();
    let pending_created = state
        .store
        .get_setting("square.oauth_pending_created_at_ms")?
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0);
    let pending_environment = if current_square_oauth_switch(
        &pending_access,
        &pending_merchant,
        pending_created,
        now_millis(),
    ) {
        state
            .store
            .get_setting("square.oauth_pending_environment")?
    } else {
        None
    };
    // Return only the application ID and credential-presence flags. Secrets,
    // tokens, merchant identity, and OAuth state never leave this endpoint.
    Ok(json!({
        "configured": configured,
        "client_id": snapshot.client_id.unwrap_or_default(),
        "secret_saved": present(&snapshot.client_secret),
        "environment": state.store.get_setting("square.oauth_environment")?
            .unwrap_or_else(|| "production".into()),
        "active_environment": if active { snapshot.environment } else { None },
        "active_authentication": if !active { None }
            else if present(&snapshot.refresh_token) { Some("oauth") }
            else { Some("access_token") },
        "pending_environment": pending_environment,
    }))
}

async fn set_square_oauth_app(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SquareOAuthAppBody>,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let _provider_guard = state.store.integration_guard(true)?;
    let client_id = body.client_id.trim();
    let submitted_secret = body.client_secret.trim();
    if !(8..=128).contains(&client_id.len()) {
        return Err(AppError::Unprocessable(
            "Enter a valid Square application ID".into(),
        ));
    }
    crate::clients::square_base_url(&body.environment)?;
    let saved_secret;
    let client_secret = if submitted_secret.is_empty() {
        let same_application = state
            .store
            .get_setting("square.oauth_client_id")?
            .as_deref()
            == Some(client_id)
            && state
                .store
                .get_setting("square.oauth_environment")?
                .as_deref()
                == Some(body.environment.as_str());
        saved_secret = state
            .store
            .get_setting("square.oauth_client_secret")?
            .unwrap_or_default();
        if !same_application || saved_secret.is_empty() {
            return Err(AppError::Unprocessable(
                "Enter the application secret for this application and environment".into(),
            ));
        }
        saved_secret.as_str()
    } else {
        submitted_secret
    };
    if !(8..=256).contains(&client_secret.len()) {
        return Err(AppError::Unprocessable(
            "Enter a valid Square application secret".into(),
        ));
    }
    state.store.update_settings(
        &[
            ("square.oauth_client_id", client_id, false),
            ("square.oauth_client_secret", client_secret, true),
            ("square.oauth_environment", &body.environment, false),
        ],
        &[],
    )?;
    Ok(json_response(square_oauth_app_value(&state)?))
}

async fn square_oauth_start(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let _provider_guard = state.store.integration_guard(true)?;
    let client_id = state
        .store
        .get_setting("square.oauth_client_id")?
        .ok_or_else(|| AppError::Conflict("Square OAuth application is not configured".into()))?;
    let environment = state
        .store
        .get_setting("square.oauth_environment")?
        .unwrap_or_else(|| "production".into());
    state.store.delete_settings(&oauth_pending_keys())?;
    let oauth_state = new_session_token();
    state.store.store_oauth_state(&oauth_state)?;
    let url = oauth_authorize_url(&environment, &client_id, &oauth_state)?;
    Ok(Redirect::to(&url).into_response())
}

async fn square_oauth_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let _provider_guard = state.store.integration_guard(true)?;
    let oauth_state = query.get("state").map(String::as_str).unwrap_or("");
    if oauth_state.is_empty() || !state.store.consume_oauth_state(oauth_state)? {
        return Ok(Redirect::to("/?square_oauth=invalid_state").into_response());
    }
    let Some(code) = query.get("code") else {
        return Ok(Redirect::to("/?square_oauth=denied").into_response());
    };
    let client_id = state
        .store
        .get_setting("square.oauth_client_id")?
        .unwrap_or_default();
    let secret = state
        .store
        .get_setting("square.oauth_client_secret")?
        .unwrap_or_default();
    let environment = state
        .store
        .get_setting("square.oauth_environment")?
        .unwrap_or_else(|| "production".into());
    let token = oauth_exchange(&environment, &client_id, &secret, Some(code), None).await?;
    let access = token
        .get("access_token")
        .and_then(Value::as_str)
        .unwrap_or("");
    let refresh = token
        .get("refresh_token")
        .and_then(Value::as_str)
        .unwrap_or("");
    let expires_at = token
        .get("expires_at")
        .and_then(Value::as_str)
        .unwrap_or("");
    let square = SquareClient::new(access, &environment)?;
    let merchant = square.merchant_id().await?;
    if square_account_changed(&state, &merchant, &environment)? {
        state.store.update_settings(
            &[
                ("square.oauth_pending_access_token", access, true),
                ("square.oauth_pending_refresh_token", refresh, true),
                ("square.oauth_pending_expires_at", expires_at, false),
                ("square.oauth_pending_merchant_id", &merchant, false),
                ("square.oauth_pending_environment", &environment, false),
                (
                    "square.oauth_pending_created_at_ms",
                    &now_millis().to_string(),
                    false,
                ),
            ],
            &[],
        )?;
        return Ok(Redirect::to("/?square_oauth=switch_required").into_response());
    }
    let revision = new_session_token();
    state.store.save_square_account_under_guard(
        &[
            ("square.access_token", access, true),
            ("square.refresh_token", refresh, true),
            ("square.token_expires_at", expires_at, false),
            ("square.environment", &environment, false),
            ("square.merchant_id", &merchant, false),
            (SQUARE_ACCOUNT_REVISION_SETTING, &revision, false),
        ],
        &[],
        false,
    )?;
    Ok(Redirect::to("/?square_oauth=connected").into_response())
}

async fn confirm_oauth_switch(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let _provider_guard = state.store.integration_guard(true)?;
    let access = state
        .store
        .get_setting("square.oauth_pending_access_token")?
        .ok_or_else(|| AppError::Conflict("No Square OAuth account switch is pending".into()))?;
    let refresh = state
        .store
        .get_setting("square.oauth_pending_refresh_token")?
        .unwrap_or_default();
    let merchant = state
        .store
        .get_setting("square.oauth_pending_merchant_id")?
        .unwrap_or_default();
    let environment = state
        .store
        .get_setting("square.oauth_pending_environment")?
        .unwrap_or_else(|| "production".into());
    let expires_at = state
        .store
        .get_setting("square.oauth_pending_expires_at")?
        .unwrap_or_default();
    let created_at_ms = state
        .store
        .get_setting("square.oauth_pending_created_at_ms")?
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0);
    let now = now_millis();
    if !current_square_oauth_switch(&access, &merchant, created_at_ms, now) {
        state.store.delete_settings(&oauth_pending_keys())?;
        return Err(AppError::Conflict(
            "The pending Square authorization expired; connect again".into(),
        ));
    }
    SquareClient::new(&access, &environment)?;
    let revision = new_session_token();
    let evidence_cleanup_pending = state.store.save_square_account_under_guard(
        &[
            ("square.access_token", &access, true),
            ("square.refresh_token", &refresh, true),
            ("square.token_expires_at", &expires_at, false),
            ("square.merchant_id", &merchant, false),
            ("square.environment", &environment, false),
            (SQUARE_ACCOUNT_REVISION_SETTING, &revision, false),
        ],
        &oauth_pending_keys(),
        true,
    )?;
    Ok(json_response(json!({
        "ok": true,
        "account_revision": revision,
        "evidence_cleanup_pending": evidence_cleanup_pending,
    })))
}

fn current_square_oauth_switch(access: &str, merchant: &str, created: i64, now: i64) -> bool {
    !access.is_empty()
        && !merchant.is_empty()
        && created <= now + 30_000
        && now.saturating_sub(created) <= 600_000
}

async fn cancel_oauth_switch(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let _provider_guard = state.store.integration_guard(true)?;
    state.store.delete_settings(&oauth_pending_keys())?;
    Ok(json_response(json!({"ok": true})))
}

fn oauth_pending_keys() -> [&'static str; 6] {
    [
        "square.oauth_pending_access_token",
        "square.oauth_pending_refresh_token",
        "square.oauth_pending_expires_at",
        "square.oauth_pending_merchant_id",
        "square.oauth_pending_environment",
        "square.oauth_pending_created_at_ms",
    ]
}

async fn protect_health(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let _provider_guard = state.store.integration_guard(false)?;
    let Some(client) = protect_from_store(&state.store)? else {
        return Ok(json_response(
            json!({"configured": false, "ok": false, "detail": "Not configured"}),
        ));
    };
    match client.cameras_with_console_identity().await {
        Ok((cameras, observed)) => match verify_protect_identity(&state.store, observed.as_deref())
        {
            Ok(()) => Ok(json_response(json!({
            "configured": true, "ok": true, "cameras": cameras.len(),
            "detail": format!("Connected — {} cameras", cameras.len())
            }))),
            Err(error) => Ok(json_response(json!({
                "configured": true, "ok": false, "detail": error.to_string()
            }))),
        },
        Err(error) => Ok(json_response(json!({
            "configured": true, "ok": false, "detail": error.to_string()
        }))),
    }
}

async fn cameras(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let _provider_guard = state.store.integration_guard(false)?;
    let client = protect_from_store(&state.store)?
        .ok_or_else(|| AppError::Conflict("UniFi Protect is not configured".into()))?;
    let (cameras, observed) = client.cameras_with_console_identity().await?;
    verify_protect_identity(&state.store, observed.as_deref())?;
    let mut response = json_response(Value::Array(cameras));
    add_generation_header(&state, &mut response)?;
    Ok(response)
}

async fn square_health(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let _provider_guard = state.store.integration_guard(false)?;
    let Some(client) = state.sync.square_client().await? else {
        return Ok(json_response(
            json!({"configured": false, "ok": false, "detail": "Not configured"}),
        ));
    };
    match client.list_locations().await {
        Ok(locations) => Ok(json_response(json!({
            "configured": true, "ok": true, "locations": locations.len(),
            "detail": format!("Connected — {} location(s)", locations.len())
        }))),
        Err(error) => Ok(json_response(json!({
            "configured": true, "ok": false, "detail": error.to_string()
        }))),
    }
}

async fn locations(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let _provider_guard = state.store.integration_guard(false)?;
    let client = state
        .sync
        .square_client()
        .await?
        .ok_or_else(|| AppError::Conflict("Square is not configured".into()))?;
    let mut response = json_response(Value::Array(client.list_locations().await?));
    add_account_revision_header(&state, &mut response)?;
    Ok(response)
}

async fn pos_devices(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let _provider_guard = state.store.integration_guard(false)?;
    Ok(json_response(Value::Array(state.store.observed_devices()?)))
}

async fn camera_preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(camera_id): AxumPath<String>,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let _provider_guard = state.store.integration_guard(false)?;
    validate_camera_id(&camera_id)?;
    let client = protect_from_store(&state.store)?
        .ok_or_else(|| AppError::Conflict("UniFi Protect is not configured".into()))?;
    let (_, observed) = client.cameras_with_console_identity().await?;
    verify_protect_identity(&state.store, observed.as_deref())?;
    let image = client.snapshot(&camera_id, None).await?;
    Ok(binary_response(StatusCode::OK, "image/jpeg", image))
}

async fn get_mapping(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let _provider_guard = state.store.integration_guard(false)?;
    let mut response = json_response(
        serde_json::to_value(state.store.get_camera_mappings()?).map_err(AppError::internal)?,
    );
    add_generation_header(&state, &mut response)?;
    add_account_revision_header(&state, &mut response)?;
    Ok(response)
}

async fn set_mapping(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CameraMappingBody>,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let _provider_guard = state.store.integration_guard(true)?;
    let expected_account = headers
        .get("x-square-account-revision")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let expected_generation = headers
        .get("x-protect-console-generation")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if expected_account.is_empty()
        || state
            .store
            .get_setting(SQUARE_ACCOUNT_REVISION_SETTING)?
            .as_deref()
            != Some(expected_account)
    {
        return Err(AppError::Conflict(
            "Square account changed; reload settings".into(),
        ));
    }
    if expected_generation.is_empty() {
        return Err(AppError::Structured(
            StatusCode::PRECONDITION_REQUIRED,
            json!({"detail": "Reload cameras before saving camera mappings"}),
        ));
    }
    if state
        .store
        .get_setting(PROTECT_CONSOLE_GENERATION_SETTING)?
        .as_deref()
        != Some(expected_generation)
    {
        return Err(AppError::Conflict(
            "Protect console changed; reload settings".into(),
        ));
    }
    state.store.replace_camera_mappings(&body.mappings)?;
    Ok(json_response(
        json!({"ok": true, "count": body.mappings.len()}),
    ))
}

async fn dashboard(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
    require_session(&state, &headers)?;
    let _provider_guard = state.store.integration_guard(false)?;
    let protect = health_protect_value(&state).await;
    let square = health_square_value(&state).await;
    let motion_config = state.store.motion_config()?;
    let mut motion = state.store.motion_summary(now_millis())?;
    motion["configured"] = Value::Bool(motion_config.enabled);
    motion["camera_name"] = Value::String(motion_config.camera_name);
    motion["last_event_ms"] = json!(motion_config.last_event_ms);
    let mut queues = state.store.queue_depths()?;
    if state
        .store
        .get_setting("protect.alarm_trigger_id")?
        .is_none()
    {
        queues["alarms_pending"] = json!(0);
    }
    Ok(json_response(json!({
        "protect": protect,
        "square": square,
        "webhook": state.store.webhook_metrics()?,
        "motion": motion,
        "transaction_flags": state.store.alarm_summary()?,
        "queues": queues,
    })))
}

async fn health_protect_value(state: &AppState) -> Value {
    match protect_from_store(&state.store) {
        Ok(Some(client)) => match client.cameras_with_console_identity().await {
            Ok((cameras, observed)) => {
                match verify_protect_identity(&state.store, observed.as_deref()) {
                    Ok(()) => {
                        json!({"configured": true, "ok": true, "detail": format!("Connected — {} cameras", cameras.len())})
                    }
                    Err(error) => {
                        json!({"configured": true, "ok": false, "detail": error.to_string()})
                    }
                }
            }
            Err(error) => json!({"configured": true, "ok": false, "detail": error.to_string()}),
        },
        _ => json!({"configured": false, "ok": false, "detail": "Not configured"}),
    }
}

async fn health_square_value(state: &AppState) -> Value {
    match state.sync.square_client().await {
        Ok(Some(client)) => match client.list_locations().await {
            Ok(locations) => {
                json!({"configured": true, "ok": true, "detail": format!("Connected — {} location(s)", locations.len())})
            }
            Err(error) => json!({"configured": true, "ok": false, "detail": error.to_string()}),
        },
        _ => json!({"configured": false, "ok": false, "detail": "Not configured"}),
    }
}

#[derive(Deserialize)]
struct MotionQuery {
    #[serde(default = "default_motion_limit")]
    limit: i64,
    #[serde(default)]
    include_matched: bool,
}

fn default_motion_limit() -> i64 {
    50
}

async fn motion_alerts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<MotionQuery>,
) -> AppResult<Response> {
    require_session(&state, &headers)?;
    let now = now_millis();
    let events = state
        .store
        .motion_alerts(query.limit, query.include_matched, now)?;
    let events = events
        .into_iter()
        .map(|event| {
            let mut value = serde_json::to_value(&event).expect("motion event serializable");
            value["deep_link"] = build_deep_link(&state, &event.camera_id, event.event_ts_ms)
                .map(Value::String)
                .unwrap_or(Value::Null);
            value
        })
        .collect::<Vec<_>>();
    Ok(json_response(json!({
        "configured": state.store.motion_config()?.enabled,
        "summary": state.store.motion_summary(now)?,
        "events": events,
    })))
}

async fn export_transactions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    require_session(&state, &headers)?;
    let mut writer = WriterBuilder::new()
        .terminator(csv::Terminator::CRLF)
        .from_writer(Vec::new());
    writer
        .write_record([
            "transaction_id",
            "timestamp",
            "amount_minor_units",
            "currency",
            "status",
            "location_id",
            "device_id",
            "device_name",
            "card_last4",
            "receipt_url",
            "protect_timeline_url",
            "note",
        ])
        .map_err(AppError::internal)?;
    for transaction in state.store.transaction_export_facts()? {
        writer
            .write_record([
                safe_csv_cell(&transaction.id),
                safe_csv_cell(&transaction.created_at),
                transaction.amount.to_string(),
                safe_csv_cell(&transaction.currency),
                safe_csv_cell(&transaction.status),
                safe_csv_cell(&transaction.location_id),
                safe_csv_cell(&transaction.device_id),
                safe_csv_cell(&transaction.device_name),
                safe_csv_cell(&transaction.card_last4),
                safe_csv_cell(&transaction.receipt_url),
                safe_csv_cell(
                    &transaction
                        .camera_id
                        .as_deref()
                        .and_then(|camera| build_deep_link(&state, camera, transaction.ts_ms))
                        .unwrap_or_default(),
                ),
                safe_csv_cell(&transaction.note),
            ])
            .map_err(AppError::internal)?;
    }
    let body = writer
        .into_inner()
        .map_err(|error| AppError::internal(error.into_error()))?;
    let mut response = binary_response(StatusCode::OK, "text/csv; charset=utf-8", body);
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"square-protect-transactions.csv\""),
    );
    Ok(response)
}

async fn get_transactions(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> AppResult<Response> {
    require_session(&state, &headers)?;
    if uri.query().is_some() {
        return Err(AppError::Unprocessable(
            "Transaction read parameters must be sent in a POST JSON body".into(),
        ));
    }
    transaction_listing(&state, TransactionQueryBody::default())
}

async fn post_transactions(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    body: Bytes,
) -> AppResult<Response> {
    require_session(&state, &headers)?;
    if uri.query().is_some() {
        return Err(AppError::Unprocessable(
            "Transaction read parameters must be sent in the JSON body".into(),
        ));
    }
    if body.len() > 2048 {
        return Err(AppError::PayloadTooLarge(
            "Transaction query payload too large".into(),
        ));
    }
    require_json_content_type(
        &headers,
        "Transaction reads require an application/json body",
    )?;
    let query: TransactionQueryBody = serde_json::from_slice(&body)
        .map_err(|_| AppError::Unprocessable("Invalid transaction query JSON".into()))?;
    transaction_listing(&state, query)
}

fn transaction_listing(state: &AppState, body: TransactionQueryBody) -> AppResult<Response> {
    let status = body.status.as_deref().unwrap_or("");
    let (transactions, snapshot) = state.store.list_transactions_page(
        body.limit,
        body.offset,
        body.snapshot,
        &body.q,
        status,
    )?;
    let values = transactions
        .into_iter()
        .map(|transaction| transaction_response(state, transaction))
        .collect::<AppResult<Vec<_>>>()?;
    let mut response = json_response(Value::Array(values));
    response.headers_mut().insert(
        HeaderName::from_static("x-transaction-snapshot"),
        HeaderValue::from_str(&snapshot.to_string()).map_err(AppError::internal)?,
    );
    Ok(response)
}

fn transaction_response(state: &AppState, transaction: TransactionRecord) -> AppResult<Value> {
    let deep_link = transaction
        .camera_id
        .as_deref()
        .and_then(|camera| build_deep_link(state, camera, transaction.ts_ms));
    let thumbnail_status = if transaction.thumbnail_path.is_some() {
        "ready"
    } else if transaction.thumbnail_retired_at.is_some() {
        "expired"
    } else if transaction.camera_id.is_none() {
        "unmapped"
    } else if transaction.thumbnail_retry_attempts > 0 {
        "retrying"
    } else {
        "queued"
    };
    Ok(json!({
        "id": transaction.id,
        "created_at": transaction.created_at,
        "ts_ms": transaction.ts_ms,
        "amount": transaction.amount,
        "currency": transaction.currency,
        "refunded_amount": transaction.refunded_amount,
        "status": transaction.status,
        "location_id": transaction.location_id,
        "device_id": transaction.device_id,
        "device_name": transaction.device_name,
        "card_last4": transaction.card_last4,
        "receipt_url": transaction.receipt_url,
        "camera_id": transaction.camera_id,
        "deep_link": deep_link,
        "thumbnail_url": transaction.thumbnail_path.as_ref().map(|_| format!("/api/thumbnails/{}", transaction.id)),
        "thumbnail_status": thumbnail_status,
        "thumbnail_retry_attempts": transaction.thumbnail_retry_attempts,
        "note": transaction.note,
        "note_revision": transaction.note_revision,
        "protect_flag_delivered_at_ms": transaction.alarm_delivered_at_ms,
        "protect_flag_offset_ms": transaction.alarm_delivered_at_ms.map(|value| value-transaction.ts_ms),
        "thumbnail_retired_at": transaction.thumbnail_retired_at,
        "thumbnail_retired_reason": transaction.thumbnail_retired_reason,
    }))
}

async fn set_transaction_note(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(transaction_id): AxumPath<String>,
    Json(body): Json<TransactionNoteBody>,
) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    if transaction_id.is_empty() || transaction_id.len() > 255 || has_control(&transaction_id) {
        return Err(AppError::Unprocessable("Invalid transaction ID".into()));
    }
    let Some((note, revision)) =
        state
            .store
            .set_transaction_note(&transaction_id, &body.note, body.revision)?
    else {
        return Err(AppError::NotFound("Transaction not found".into()));
    };
    Ok(json_response(json!({
        "ok": true, "id": transaction_id, "note": note, "note_revision": revision
    })))
}

async fn thumbnail(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(transaction_id): AxumPath<String>,
) -> AppResult<Response> {
    require_session(&state, &headers)?;
    let _provider_guard = state.store.integration_guard(false)?;
    let transaction = state
        .store
        .get_transaction(&transaction_id)?
        .ok_or_else(|| AppError::NotFound("No thumbnail for this transaction".into()))?;
    if transaction.thumbnail_retired_at.is_some() {
        return Err(AppError::Gone(
            "Thumbnail expired under the configured retention policy".into(),
        ));
    }
    let filename = transaction
        .thumbnail_path
        .ok_or_else(|| AppError::NotFound("No thumbnail for this transaction".into()))?;
    if Path::new(&filename)
        .file_name()
        .and_then(|value| value.to_str())
        != Some(&filename)
    {
        return Err(AppError::NotFound("Thumbnail not found".into()));
    }
    let path = state.store.thumbnail_dir().join(&filename);
    let bytes = match read_thumbnail(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(transaction_id = %transaction_id, %error, "could not read thumbnail");
            if state
                .store
                .requeue_missing_thumbnail(&transaction_id, &filename)?
            {
                let engine = state.sync.clone();
                tokio::spawn(async move {
                    if let Err(error) = engine.drain_verified_protect_queues().await {
                        tracing::warn!(%error, "missing thumbnail recapture deferred");
                    }
                });
            }
            return Err(AppError::NotFound("Thumbnail not found".into()));
        }
    };
    Ok(binary_response(StatusCode::OK, "image/jpeg", bytes))
}

async fn manual_sync(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
    require_admin(&state, &headers)?;
    let Some(ingested) = state.sync.try_sync().await? else {
        return Err(AppError::Conflict("A sync is already in progress".into()));
    };
    Ok(json_response(json!({"ok": true, "ingested": ingested})))
}

async fn protect_motion_get(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
) -> AppResult<Response> {
    validate_motion_transport(peer, &headers, &uri)?;
    let token = motion_token(&headers)?;
    let config = state.store.authenticate_motion(&token)?;
    if headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value != "0")
    {
        return Err(AppError::BadRequest(
            "Protect motion GET webhook cannot include a body".into(),
        ));
    }
    let received = now_millis();
    let material = format!("{}\0{}", config.camera_id, received / 5000);
    let key = format!("get:{}", hex::encode(Sha256::digest(material.as_bytes())));
    state
        .store
        .record_motion(&token, &key, received, received, "get", "", &[])?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn protect_motion_post(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    body: Bytes,
) -> AppResult<Response> {
    validate_motion_transport(peer, &headers, &uri)?;
    let token = motion_token(&headers)?;
    let config = state.store.authenticate_motion(&token)?;
    require_json_content_type(&headers, "Protect motion webhooks require application/json")?;
    if body.is_empty() || body.len() > 32 * 1024 {
        return Err(AppError::PayloadTooLarge(
            "Protect motion webhook payload too large".into(),
        ));
    }
    let received = now_millis();
    let delivery = parse_motion_payload(
        &body,
        received,
        received - config.retention_days * 86_400_000,
    )?;
    state.store.record_motion(
        &token,
        &delivery.event_key,
        delivery.timestamp,
        received,
        "post",
        &delivery.alarm_name,
        &delivery.devices,
    )?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn square_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let _provider_guard = state.store.integration_guard(false)?;
    if body.len() > 1024 * 1024 {
        return Err(AppError::PayloadTooLarge(
            "Webhook payload too large".into(),
        ));
    }
    let signature = headers
        .get("x-square-hmacsha256-signature")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let (key, url, merchant) = state.store.square_webhook_config()?;
    if key.is_empty() || url.is_empty() {
        return Err(AppError::Forbidden("Webhook not configured".into()));
    }
    if !verify_square_webhook_signature(&key, &url, &body, signature) {
        return Err(AppError::Unauthorized("Invalid webhook signature".into()));
    }
    let received = now_millis();
    state.store.record_webhook_delivery(received)?;
    let event: Value = serde_json::from_slice(&body)
        .map_err(|_| AppError::Unprocessable("Invalid JSON payload".into()))?;
    if event.get("merchant_id").and_then(Value::as_str) != Some(&merchant) {
        return Ok(json_response(json!({"ok": true, "ignored": true})));
    }
    let event_type = event.get("type").and_then(Value::as_str).unwrap_or("");
    if !matches!(event_type, "payment.created" | "payment.updated") {
        return Ok(json_response(json!({"ok": true, "ignored": true})));
    }
    let receipt = webhook_receipt_key(event.get("event_id"), &body);
    let event_created = event
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.timestamp_millis())
        .filter(|value| *value >= 0);
    if state.store.webhook_receipt_exists(&receipt)? {
        state
            .store
            .record_webhook_receipt(&receipt, event_type, received, event_created)?;
        return Ok(json_response(json!({"ok": true, "ignored": true})));
    }
    let Some(payment) = event
        .pointer("/data/object/payment")
        .filter(|value| value.as_object().is_some_and(|object| !object.is_empty()))
    else {
        return Ok(json_response(json!({"ok": true, "ignored": true})));
    };
    state.sync.ingest_payment(payment).await?;
    state
        .store
        .record_webhook_receipt(&receipt, event_type, received, event_created)?;
    let engine = state.sync.clone();
    tokio::spawn(async move {
        if let Err(error) = engine.drain_verified_protect_queues().await {
            tracing::warn!(%error, "Protect work drain deferred");
        }
    });
    Ok(json_response(json!({"ok": true})))
}

fn require_session(state: &AppState, headers: &HeaderMap) -> AppResult<SessionUser> {
    let token = session_token(headers)
        .ok_or_else(|| AppError::Unauthorized("Authentication required".into()))?;
    state
        .store
        .session_user(&token)?
        .ok_or_else(|| AppError::Unauthorized("Authentication required".into()))
}

fn require_admin(state: &AppState, headers: &HeaderMap) -> AppResult<SessionUser> {
    let user = require_session(state, headers)?;
    if user.role != ROLE_ADMIN {
        return Err(AppError::Forbidden("Administrator access required".into()));
    }
    Ok(user)
}

fn session_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|cookie| cookie.trim().split_once('='))
        .find_map(|(name, value)| (name == SESSION_COOKIE).then(|| value.to_owned()))
}

fn session_cookie(token: &str, secure: bool) -> AppResult<HeaderValue> {
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200{}",
        if secure { "; Secure" } else { "" }
    ))
    .map_err(AppError::internal)
}

fn json_response(value: Value) -> Response {
    Json(value).into_response()
}

fn binary_response(status: StatusCode, content_type: &str, bytes: Vec<u8>) -> Response {
    let mut response = (status, bytes).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
}

fn validate_password(value: &str) -> AppResult<()> {
    if !(8..=256).contains(&value.len()) {
        return Err(AppError::Unprocessable(
            "Password must be 8 to 256 characters".into(),
        ));
    }
    Ok(())
}

async fn hash_password_async(password: String) -> AppResult<String> {
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(AppError::internal)?
}

fn integer_setting(store: &Store, key: &str, default: i64) -> i64 {
    store
        .get_setting(key)
        .ok()
        .flatten()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn add_generation_header(state: &AppState, response: &mut Response) -> AppResult<()> {
    response.headers_mut().insert(
        HeaderName::from_static("x-protect-console-generation"),
        HeaderValue::from_str(
            &state
                .store
                .get_setting(PROTECT_CONSOLE_GENERATION_SETTING)?
                .unwrap_or_default(),
        )
        .map_err(AppError::internal)?,
    );
    Ok(())
}

fn add_account_revision_header(state: &AppState, response: &mut Response) -> AppResult<()> {
    response.headers_mut().insert(
        HeaderName::from_static("x-square-account-revision"),
        HeaderValue::from_str(
            &state
                .store
                .get_setting(SQUARE_ACCOUNT_REVISION_SETTING)?
                .unwrap_or_default(),
        )
        .map_err(AppError::internal)?,
    );
    Ok(())
}

fn explicit_loopback_request(config: &Config, peer: SocketAddr, headers: &HeaderMap) -> bool {
    config.is_loopback_bind()
        && peer.ip().is_loopback()
        && !has_forwarding_headers(headers)
        && headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .and_then(authority_host)
            .is_some_and(is_loopback_host)
        && headers
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .is_none_or(loopback_origin)
}

fn authority_host(authority: &str) -> Option<&str> {
    if authority.is_empty()
        || authority.contains(['/', '\\', '@', '?', '#', ','])
        || authority.chars().any(char::is_whitespace)
    {
        return None;
    }
    if authority.starts_with('[') {
        let close = authority.find(']')?;
        let host = &authority[1..close];
        if host.is_empty() {
            return None;
        }
        let suffix = &authority[close + 1..];
        if !suffix.is_empty() && (!suffix.starts_with(':') || !valid_authority_port(&suffix[1..])) {
            return None;
        }
        Some(host)
    } else {
        let host = match authority.split_once(':') {
            Some((host, port)) if valid_authority_port(port) => host,
            Some(_) => return None,
            None => authority,
        };
        if host.is_empty() {
            return None;
        }
        Some(host)
    }
}

fn valid_authority_port(port: &str) -> bool {
    !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|port| port != 0)
}

fn is_loopback_host(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    host.trim_end_matches('.').eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|value| value.is_loopback())
}

fn loopback_origin(origin: &str) -> bool {
    Url::parse(origin)
        .ok()
        .filter(|url| matches!(url.scheme(), "http" | "https"))
        .and_then(|url| url.host_str().map(is_loopback_host))
        .unwrap_or(false)
}

fn has_forwarding_headers(headers: &HeaderMap) -> bool {
    headers.keys().any(|name| {
        let name = name.as_str();
        name.starts_with("x-forwarded-")
            || matches!(
                name,
                "forwarded" | "via" | "x-real-ip" | "cf-connecting-ip" | "true-client-ip"
            )
    })
}

fn validate_https_url(value: &str) -> AppResult<String> {
    let value = value.trim();
    if !(12..=512).contains(&value.len()) {
        return Err(AppError::Unprocessable(
            "Notification URL is invalid".into(),
        ));
    }
    let url = Url::parse(value)
        .map_err(|_| AppError::Unprocessable("Notification URL is invalid".into()))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.username() != ""
        || url.password().is_some()
    {
        return Err(AppError::Unprocessable(
            "Notification URL must be https:// and publicly reachable".into(),
        ));
    }
    Ok(value.to_owned())
}

fn validate_deep_link_template(template: &str) -> AppResult<()> {
    if template.len() > 2048
        || !template.starts_with("https://{host}/")
        || !template.contains("{camera_id}")
        || !template.contains("{ts_ms}")
        || template.matches("{host}").count() != 1
    {
        return Err(AppError::Unprocessable(
            "Timeline template must use https:// with {host} as the hostname and include {camera_id} and {ts_ms}".into(),
        ));
    }
    Ok(())
}

fn build_deep_link(state: &AppState, camera_id: &str, ts_ms: i64) -> Option<String> {
    let host = state.store.get_setting("protect.host").ok().flatten()?;
    let template = state
        .store
        .get_setting("deep_link_template")
        .ok()
        .flatten()
        .filter(|value| validate_deep_link_template(value).is_ok())
        .unwrap_or_else(|| DEFAULT_DEEP_LINK_TEMPLATE.into());
    Some(
        template
            .replace("{host}", &host)
            .replace("{camera_id}", camera_id)
            .replace("{ts_ms}", &ts_ms.to_string()),
    )
}

fn safe_csv_cell(value: &str) -> String {
    let text = value
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n");
    let candidate = text
        .trim_start()
        .trim_start_matches('\u{feff}')
        .trim_start();
    if text.starts_with(['\t', '\r', '\n']) || candidate.starts_with(['=', '+', '-', '@']) {
        format!("'{text}")
    } else {
        text
    }
}

fn require_json_content_type(headers: &HeaderMap, message: &str) -> AppResult<()> {
    let media_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if media_type == "application/json" || media_type.ends_with("+json") {
        Ok(())
    } else {
        Err(AppError::UnsupportedMediaType(message.into()))
    }
}

fn validate_motion_transport(peer: SocketAddr, headers: &HeaderMap, uri: &Uri) -> AppResult<()> {
    if has_forwarding_headers(headers) || !is_trusted_lan(peer.ip()) {
        return Err(AppError::Forbidden(
            "Protect motion webhook accepts direct LAN requests only".into(),
        ));
    }
    if uri.query().is_some() {
        return Err(AppError::BadRequest(
            "Protect motion webhook does not accept URL parameters".into(),
        ));
    }
    Ok(())
}

fn is_trusted_lan(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => value.is_private() || value.is_loopback(),
        IpAddr::V6(value) => {
            value.is_loopback()
                || (value.segments()[0] & 0xfe00) == 0xfc00
                || (value.segments()[0] & 0xffc0) == 0xfe80
                || value
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| mapped.is_private() || mapped.is_loopback())
        }
    }
}

fn motion_token(headers: &HeaderMap) -> AppResult<String> {
    let custom = headers
        .get("x-spi-webhook-token")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .unwrap_or("");
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, token)| token.trim())
        .unwrap_or("");
    if !custom.is_empty() && !bearer.is_empty() && custom != bearer {
        return Err(AppError::Unauthorized(
            "Invalid Protect motion webhook token".into(),
        ));
    }
    Ok(if custom.is_empty() { bearer } else { custom }.to_owned())
}

struct MotionDelivery {
    timestamp: i64,
    alarm_name: String,
    devices: Vec<String>,
    event_key: String,
}

fn parse_motion_payload(body: &[u8], received: i64, oldest: i64) -> AppResult<MotionDelivery> {
    let payload: Value = serde_json::from_slice(body)
        .map_err(|_| AppError::Unprocessable("Protect motion payload is not valid JSON".into()))?;
    let timestamp = payload
        .get("timestamp")
        .and_then(Value::as_i64)
        .ok_or_else(|| {
            AppError::Unprocessable("Protect motion timestamp must be Unix milliseconds".into())
        })?;
    if timestamp < oldest {
        return Err(AppError::Unprocessable(
            "Protect motion timestamp is too old".into(),
        ));
    }
    if timestamp > received + 300_000 {
        return Err(AppError::Unprocessable(
            "Protect motion timestamp is in the future".into(),
        ));
    }
    let alarm = payload
        .get("alarm")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::Unprocessable("Protect motion alarm is invalid".into()))?;
    let alarm_name = alarm
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_owned();
    if alarm_name.len() > 256 || has_control(&alarm_name) {
        return Err(AppError::Unprocessable(
            "Protect motion alarm name is invalid".into(),
        ));
    }
    let conditions = bounded_alarm_entries(alarm.get("conditions"), "conditions")?;
    let triggers = bounded_alarm_entries(alarm.get("triggers"), "triggers")?;
    let mut motion = false;
    let mut canonical = Vec::<(String, String)>::new();
    let mut devices = Vec::new();
    for wrapper in conditions {
        let condition = wrapper.get("condition").unwrap_or(wrapper);
        if condition
            .get("source")
            .and_then(Value::as_str)
            .is_some_and(|value| value.eq_ignore_ascii_case("motion"))
        {
            motion = true;
        }
    }
    for trigger in triggers {
        let key = trigger
            .get("key")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        let device = trigger
            .get("device")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if key.len() > 64 || device.len() > 128 || has_control(key) || has_control(device) {
            return Err(AppError::Unprocessable(
                "Protect motion trigger is invalid".into(),
            ));
        }
        motion |= key.eq_ignore_ascii_case("motion");
        canonical.push((key.to_owned(), device.to_owned()));
        if !device.is_empty() && !devices.iter().any(|value| value == device) {
            devices.push(device.to_owned());
        }
    }
    if !motion {
        return Err(AppError::Unprocessable(
            "Protect alarm did not report motion".into(),
        ));
    }
    canonical.sort();
    let canonical = serde_json::to_vec(&json!({
        "timestamp": timestamp,
        "alarm_name": alarm_name,
        "triggers": canonical,
    }))
    .map_err(AppError::internal)?;
    Ok(MotionDelivery {
        timestamp,
        alarm_name,
        devices,
        event_key: format!("post:{}", hex::encode(Sha256::digest(&canonical))),
    })
}

fn bounded_alarm_entries<'a>(value: Option<&'a Value>, label: &str) -> AppResult<&'a [Value]> {
    match value {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(entries))
            if entries.len() <= 64 && entries.iter().all(Value::is_object) =>
        {
            Ok(entries)
        }
        _ => Err(AppError::Unprocessable(format!(
            "Protect motion {label} is invalid"
        ))),
    }
}

fn webhook_receipt_key(event_id: Option<&Value>, body: &[u8]) -> String {
    let material = event_id
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 256 && !has_control(value))
        .map(|value| [b"event-id\0".as_slice(), value.as_bytes()].concat())
        .unwrap_or_else(|| [b"signed-body\0".as_slice(), body].concat());
    hex::encode(Sha256::digest(material))
}

fn has_control(value: &str) -> bool {
    value
        .chars()
        .any(|character| character < ' ' || character == '\u{7f}')
}

fn discover_unifi(extra_host: Option<&str>) -> AppResult<Vec<Value>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    for _ in 0..3 {
        let _ = socket.send_to(&[1, 0, 0, 0], (Ipv4Addr::BROADCAST, 10001));
    }
    if let Some(host) = extra_host {
        let _ = socket.send_to(&[1, 0, 0, 0], (host, 10001));
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut devices = HashMap::<IpAddr, Value>::new();
    while Instant::now() < deadline {
        let mut buffer = [0_u8; 4096];
        match socket.recv_from(&mut buffer) {
            Ok((length, source)) => {
                if let Some(device) = parse_discovery_response(&buffer[..length], source.ip()) {
                    devices.insert(source.ip(), device);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
    }
    let mut devices: Vec<_> = devices.into_values().collect();
    devices.sort_by_key(|value| {
        (
            !value
                .get("is_console")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            value
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase(),
        )
    });
    Ok(devices)
}

fn parse_discovery_response(bytes: &[u8], source: IpAddr) -> Option<Value> {
    if bytes.len() < 8 || bytes[..2] != [1, 0] {
        return None;
    }
    let declared = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if declared != bytes.len() - 4 {
        return None;
    }
    let mut name = None;
    let mut hostname = None;
    let mut model = None;
    let mut firmware = None;
    let mut index = 4;
    while index < bytes.len() {
        if index + 3 > bytes.len() {
            return None;
        }
        let kind = bytes[index];
        let length = u16::from_be_bytes([bytes[index + 1], bytes[index + 2]]) as usize;
        let end = index + 3 + length;
        if end > bytes.len() {
            return None;
        }
        let text = String::from_utf8_lossy(&bytes[index + 3..end]).into_owned();
        match kind {
            0x06 => name = Some(text),
            0x0b => hostname = Some(text),
            0x0c => model = Some(text),
            0x14 if model.is_none() => model = Some(text),
            0x03 => firmware = Some(text),
            _ => {}
        }
        index = end;
    }
    if name.is_none() && hostname.is_none() && model.is_none() {
        return None;
    }
    let model = model.unwrap_or_default();
    let upper = model.to_ascii_uppercase();
    let console = ["UNVR", "UDM", "UDR", "UDW", "UCK", "UCG", "UX", "UNAS"]
        .iter()
        .any(|prefix| upper.starts_with(prefix));
    Some(json!({
        "ip": source.to_string(),
        "name": name.or(hostname.clone()).unwrap_or_else(|| source.to_string()),
        "hostname": hostname.unwrap_or_default(),
        "model": model,
        "firmware": firmware.unwrap_or_default(),
        "is_console": console,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, extract::ConnectInfo, http::Request};
    use http_body_util::BodyExt;
    use std::{net::Ipv6Addr, path::PathBuf};
    use tower::ServiceExt;

    const TEST_BOOTSTRAP_SECRET: &str = "rust-http-test-bootstrap-secret-0001";
    const ADMIN_PASSWORD: &str = "rust-admin-test-password";

    fn test_state(data_dir: PathBuf) -> AppState {
        let store = Store::open(&data_dir).unwrap();
        AppState::new(
            store,
            Config {
                data_dir,
                static_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("app/static"),
                bind_host: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 8000,
                tls_enabled: false,
                tls_certfile: None,
                tls_keyfile: None,
                cookie_secure: false,
                poll_interval: None,
                bootstrap_secret: Some(TEST_BOOTSTRAP_SECRET.into()),
            },
        )
    }

    fn http_request(method: &str, uri: &str, body: Value, cookie: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, "localhost:8000")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        let mut request = builder.body(Body::from(body.to_string())).unwrap();
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            41_000,
        )));
        request
    }

    async fn response_json_value(response: Response) -> Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn response_cookie(response: &Response) -> String {
        response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }

    fn authenticated_state(data_dir: PathBuf) -> (AppState, String) {
        let state = test_state(data_dir);
        assert!(
            state
                .store
                .create_initial_admin("test-only-password-hash")
                .unwrap()
        );
        let admin = state.store.user_for_login("admin").unwrap().unwrap();
        let token = "direct-admin-session-token";
        state
            .store
            .create_session(token, admin.id, admin.auth_revision, "127.0.0.1")
            .unwrap();
        (state, format!("{SESSION_COOKIE}={token}"))
    }

    async fn response_bytes(response: Response) -> Vec<u8> {
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec()
    }

    #[test]
    fn spreadsheet_cells_are_formula_safe() {
        assert_eq!(safe_csv_cell("=1+1"), "'=1+1");
        assert_eq!(safe_csv_cell("  @SUM(A:A)"), "'  @SUM(A:A)");
        assert_eq!(safe_csv_cell("normal"), "normal");
    }

    #[test]
    fn trusted_lan_does_not_accept_public_peers() {
        assert!(is_trusted_lan("10.1.2.3".parse().unwrap()));
        assert!(is_trusted_lan(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_trusted_lan("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn trusted_lan_covers_private_link_local_and_mapped_addresses() {
        for address in [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "fd00::1",
            "fe80::1",
            "::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_trusted_lan(address.parse().unwrap()), "{address}");
        }
        for address in ["1.1.1.1", "8.8.8.8", "2001:4860:4860::8888"] {
            assert!(!is_trusted_lan(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn host_and_origin_parsing_fail_closed_at_authority_boundaries() {
        for (authority, expected) in [
            ("localhost", Some("localhost")),
            ("localhost:8000", Some("localhost")),
            ("127.0.0.1:443", Some("127.0.0.1")),
            ("[::1]:8000", Some("::1")),
        ] {
            assert_eq!(authority_host(authority), expected);
        }
        for invalid in [
            "",
            "localhost:",
            "localhost:+1",
            "localhost:0",
            "localhost:65536",
            "localhost/path",
            "user@localhost",
            "localhost?x=1",
            "localhost #fragment",
            "[::1",
            "[]:8000",
            "[::1]:bad",
            "[::1]:0",
        ] {
            assert!(authority_host(invalid).is_none(), "{invalid:?}");
        }
        assert!(loopback_origin("http://localhost:8000"));
        assert!(loopback_origin("https://127.0.0.1"));
        assert!(loopback_origin("http://[::1]:9443"));
        assert!(!loopback_origin("https://10.0.0.1"));
        assert!(!loopback_origin("file:///tmp/index.html"));
    }

    #[test]
    fn deep_link_templates_require_https_host_and_bounded_placeholders() {
        for valid in [
            DEFAULT_DEEP_LINK_TEMPLATE,
            "https://{host}/protect/{camera_id}/timeline?time={ts_ms}",
        ] {
            validate_deep_link_template(valid).unwrap();
        }
        for invalid in [
            "http://{host}/{camera_id}?t={ts_ms}",
            "https://example.test/{camera_id}?t={ts_ms}",
            "https://{host}/timeline?t={ts_ms}",
            "https://{host}/timeline/{camera_id}",
            "https://{host}.{host}/{camera_id}?t={ts_ms}",
            "javascript:https://{host}/{camera_id}/{ts_ms}",
        ] {
            assert!(matches!(
                validate_deep_link_template(invalid),
                Err(AppError::Unprocessable(_))
            ));
        }
    }

    #[test]
    fn csv_formula_neutralization_preserves_rfc4180_newlines() {
        for dangerous in [
            "+1",
            "-2",
            "@SUM(A:A)",
            "\tformula",
            "\nformula",
            " \u{feff}=1",
        ] {
            assert!(safe_csv_cell(dangerous).starts_with('\''), "{dangerous:?}");
        }
        assert_eq!(safe_csv_cell("line1\nline2"), "line1\r\nline2");
        assert_eq!(safe_csv_cell("line1\rline2"), "line1\r\nline2");
    }

    #[test]
    fn content_type_accepts_json_suffixes_only() {
        for value in [
            "application/json",
            "application/json; charset=utf-8",
            "application/problem+json",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_str(value).unwrap());
            require_json_content_type(&headers, "json required").unwrap();
        }
        for value in ["", "text/json", "text/plain", "application/jsonp"] {
            let mut headers = HeaderMap::new();
            if !value.is_empty() {
                headers.insert(header::CONTENT_TYPE, HeaderValue::from_str(value).unwrap());
            }
            assert!(matches!(
                require_json_content_type(&headers, "json required"),
                Err(AppError::UnsupportedMediaType(_))
            ));
        }
    }

    #[test]
    fn motion_tokens_accept_one_header_form_and_reject_ambiguity() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-spi-webhook-token",
            HeaderValue::from_static("custom-token"),
        );
        assert_eq!(motion_token(&headers).unwrap(), "custom-token");
        headers.clear();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer bearer-token"),
        );
        assert_eq!(motion_token(&headers).unwrap(), "bearer-token");
        headers.insert(
            "x-spi-webhook-token",
            HeaderValue::from_static("other-token"),
        );
        assert!(matches!(
            motion_token(&headers),
            Err(AppError::Unauthorized(_))
        ));
        headers.insert(
            "x-spi-webhook-token",
            HeaderValue::from_static("bearer-token"),
        );
        assert_eq!(motion_token(&headers).unwrap(), "bearer-token");
    }

    #[test]
    fn motion_payload_is_normalized_deduped_and_time_bounded() {
        let received = 1_800_000_000_000;
        let body = json!({
            "timestamp": received - 1_000,
            "alarm": {
                "name": "Register motion",
                "conditions": [{"condition": {"source": "motion"}}],
                "triggers": [
                    {"key": "motion", "device": "sensor-2"},
                    {"key": "motion", "device": "sensor-1"},
                    {"key": "motion", "device": "sensor-1"}
                ]
            }
        });
        let parsed = parse_motion_payload(
            &serde_json::to_vec(&body).unwrap(),
            received,
            received - 86_400_000,
        )
        .unwrap();
        assert_eq!(parsed.timestamp, received - 1_000);
        assert_eq!(parsed.alarm_name, "Register motion");
        assert_eq!(parsed.devices, ["sensor-2", "sensor-1"]);
        assert!(parsed.event_key.starts_with("post:"));
        assert_eq!(parsed.event_key.len(), 69);

        for invalid in [
            json!({}),
            json!({"timestamp": received - 86_400_001, "alarm": {"conditions": [{"condition": {"source": "motion"}}]}}),
            json!({"timestamp": received + 300_001, "alarm": {"conditions": [{"condition": {"source": "motion"}}]}}),
            json!({"timestamp": received, "alarm": {"conditions": []}}),
            json!({"timestamp": received, "alarm": {"conditions": "motion"}}),
        ] {
            assert!(matches!(
                parse_motion_payload(
                    &serde_json::to_vec(&invalid).unwrap(),
                    received,
                    received - 86_400_000
                ),
                Err(AppError::Unprocessable(_))
            ));
        }
    }

    #[test]
    fn webhook_receipt_key_prefers_safe_event_id_and_falls_back_to_body() {
        let body = br#"{"type":"payment.updated"}"#;
        let first = webhook_receipt_key(Some(&json!("event-1")), body);
        let second = webhook_receipt_key(Some(&json!("event-1")), b"different");
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert_ne!(webhook_receipt_key(Some(&json!("event-2")), body), first);
        assert_eq!(
            webhook_receipt_key(Some(&json!("")), body),
            webhook_receipt_key(None, body)
        );
    }

    #[test]
    fn discovery_parser_accepts_console_tlv_and_rejects_truncation() {
        fn field(kind: u8, value: &str) -> Vec<u8> {
            let mut bytes = vec![kind];
            bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
            bytes
        }
        let mut payload = Vec::new();
        payload.extend(field(0x06, "Example UNVR"));
        payload.extend(field(0x0b, "example-unvr"));
        payload.extend(field(0x0c, "UNVRPRO"));
        payload.extend(field(0x03, "4.1.22"));
        let mut response = vec![1, 0];
        response.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        response.extend(payload);
        let parsed = parse_discovery_response(&response, "10.0.0.20".parse().unwrap()).unwrap();
        assert_eq!(parsed["ip"], "10.0.0.20");
        assert_eq!(parsed["name"], "Example UNVR");
        assert_eq!(parsed["model"], "UNVRPRO");
        assert_eq!(parsed["is_console"], true);
        assert!(parse_discovery_response(b"garbage", "10.0.0.20".parse().unwrap()).is_none());
        response.pop();
        assert!(parse_discovery_response(&response, "10.0.0.20".parse().unwrap()).is_none());
    }

    #[tokio::test]
    async fn square_oauth_settings_persist_without_exposing_secrets_or_switching_accounts() {
        let temp = tempfile::tempdir().unwrap();
        let (state, cookie) = authenticated_state(temp.path().to_owned());
        state
            .store
            .update_settings(
                &[
                    ("square.access_token", "test-sandbox-access", true),
                    ("square.environment", "sandbox", false),
                ],
                &[],
            )
            .unwrap();
        let app = build_router(state.clone());
        let response = app.clone().oneshot(http_request("PUT", "/api/settings/square/oauth-app",
            json!({"client_id":"test-production-app", "client_secret":"test-production-secret", "environment":"production"}),
            Some(&cookie))).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let expected = json!({
            "configured": true, "client_id": "test-production-app", "secret_saved": true,
            "environment": "production", "active_environment": "sandbox",
            "active_authentication": "access_token", "pending_environment": null,
        });
        assert_eq!(response_json_value(response).await, expected);

        // A fresh process can restore the form without reading secrets into the browser.
        let reloaded = build_router(test_state(temp.path().to_owned()));
        let response = reloaded
            .oneshot(http_request(
                "GET",
                "/api/settings/square/oauth-app",
                json!({}),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        assert_eq!(response_json_value(response).await, expected);

        // Leaving the secret blank preserves it only for the same application/environment.
        for (client_id, environment, expected_status) in [
            ("test-production-app", "production", StatusCode::OK),
            (
                "test-different-app",
                "production",
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                "test-production-app",
                "sandbox",
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ] {
            let response = app
                .clone()
                .oneshot(http_request(
                    "PUT",
                    "/api/settings/square/oauth-app",
                    json!({"client_id":client_id, "client_secret":"", "environment":environment}),
                    Some(&cookie),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), expected_status);
        }
        assert_eq!(
            state
                .store
                .get_setting("square.oauth_client_secret")
                .unwrap()
                .as_deref(),
            Some("test-production-secret")
        );
        assert_eq!(
            state
                .store
                .get_setting("square.oauth_client_id")
                .unwrap()
                .as_deref(),
            Some("test-production-app")
        );
        assert_eq!(
            state
                .store
                .get_setting("square.oauth_environment")
                .unwrap()
                .as_deref(),
            Some("production")
        );
        assert_eq!(
            state
                .store
                .get_setting("square.access_token")
                .unwrap()
                .as_deref(),
            Some("test-sandbox-access")
        );
        assert_eq!(
            state
                .store
                .get_setting("square.environment")
                .unwrap()
                .as_deref(),
            Some("sandbox")
        );
    }

    #[tokio::test]
    async fn square_oauth_settings_show_only_current_switches_and_require_initial_secret() {
        let temp = tempfile::tempdir().unwrap();
        let (state, cookie) = authenticated_state(temp.path().to_owned());
        let app = build_router(state.clone());
        let response = app.clone().oneshot(http_request("PUT", "/api/settings/square/oauth-app",
            json!({"client_id":"test-production-app", "client_secret":"", "environment":"production"}),
            Some(&cookie))).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            !square_oauth_app_value(&state).unwrap()["configured"]
                .as_bool()
                .unwrap()
        );
        state
            .store
            .update_settings(
                &[
                    (
                        "square.oauth_pending_access_token",
                        "test-pending-access",
                        true,
                    ),
                    (
                        "square.oauth_pending_refresh_token",
                        "test-pending-refresh",
                        true,
                    ),
                    (
                        "square.oauth_pending_merchant_id",
                        "TEST_PENDING_MERCHANT",
                        false,
                    ),
                    ("square.oauth_pending_environment", "production", false),
                ],
                &[],
            )
            .unwrap();
        for (age, pending) in [
            (0, json!("production")),
            (601_000, Value::Null),
            (-60_000, Value::Null),
        ] {
            state
                .store
                .set_setting(
                    "square.oauth_pending_created_at_ms",
                    &(now_millis() - age).to_string(),
                    false,
                )
                .unwrap();
            let response = app
                .clone()
                .oneshot(http_request(
                    "GET",
                    "/api/settings/square/oauth-app",
                    json!({}),
                    Some(&cookie),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response_json_value(response).await;
            assert_eq!(body["pending_environment"], pending);
            assert_eq!(body["active_environment"], Value::Null);
            assert!(!body.to_string().contains("test-pending"));
            assert!(!body.to_string().contains("TEST_PENDING_MERCHANT"));
        }
        assert_eq!(
            state
                .store
                .get_setting("square.oauth_pending_access_token")
                .unwrap()
                .as_deref(),
            Some("test-pending-access")
        );
    }

    #[tokio::test]
    async fn square_webhook_registration_is_forbidden_even_for_admins() {
        for environment in ["production", "sandbox"] {
            let temp = tempfile::tempdir().unwrap();
            let (state, cookie) = authenticated_state(temp.path().to_owned());
            state
                .store
                .set_setting("square.environment", environment, false)
                .unwrap();
            state
                .store
                .set_setting(
                    "square.webhook_signature_key",
                    "test-existing-signature",
                    true,
                )
                .unwrap();
            state
                .store
                .set_setting(
                    "square.webhook_url",
                    "https://example.com/webhooks/square",
                    false,
                )
                .unwrap();
            let app = build_router(state.clone());
            let response = app
                .oneshot(http_request(
                    "POST",
                    "/api/settings/square/webhook/register",
                    json!({"notification_url": "https://example.com/replacement"}),
                    Some(&cookie),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let body = response_json_value(response).await;
            assert!(body.to_string().contains("read-only"));
            assert_eq!(
                state
                    .store
                    .get_setting("square.webhook_signature_key")
                    .unwrap()
                    .as_deref(),
                Some("test-existing-signature")
            );
            assert_eq!(
                state
                    .store
                    .get_setting("square.webhook_url")
                    .unwrap()
                    .as_deref(),
                Some("https://example.com/webhooks/square")
            );
        }
    }

    #[tokio::test]
    async fn browser_auth_contract_and_role_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        let app = build_router(test_state(temp.path().to_owned()));

        let status = app
            .clone()
            .oneshot(http_request("GET", "/api/status", json!({}), None))
            .await
            .unwrap();
        assert_eq!(status.status(), StatusCode::OK);
        assert_eq!(status.headers()[header::CACHE_CONTROL], "private, no-store");
        assert_eq!(status.headers()["x-frame-options"], "DENY");
        assert!(status.headers().contains_key("content-security-policy"));
        assert_eq!(response_json_value(status).await["backend"], "rust");

        let setup = app
            .clone()
            .oneshot(http_request(
                "POST",
                "/api/setup",
                json!({
                    "password": ADMIN_PASSWORD,
                    "bootstrap_secret": TEST_BOOTSTRAP_SECRET,
                }),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(setup.status(), StatusCode::OK);

        let login = app
            .clone()
            .oneshot(http_request(
                "POST",
                "/api/login",
                json!({"username": "admin", "password": ADMIN_PASSWORD}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK);
        let admin_cookie = response_cookie(&login);
        assert!(
            login.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains("HttpOnly")
        );

        let created = app
            .clone()
            .oneshot(http_request(
                "POST",
                "/api/users",
                json!({
                    "username": "audit.viewer",
                    "password": "viewer-test-password",
                    "role": "viewer",
                }),
                Some(&admin_cookie),
            ))
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);

        let viewer_login = app
            .clone()
            .oneshot(http_request(
                "POST",
                "/api/login",
                json!({"username": "audit.viewer", "password": "viewer-test-password"}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(viewer_login.status(), StatusCode::OK);
        let viewer_cookie = response_cookie(&viewer_login);

        let forbidden = app
            .clone()
            .oneshot(http_request(
                "GET",
                "/api/users",
                json!({}),
                Some(&viewer_cookie),
            ))
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let forbidden = app
            .clone()
            .oneshot(http_request(
                "GET",
                "/api/settings/square/oauth-app",
                json!({}),
                Some(&viewer_cookie),
            ))
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let readable = app
            .oneshot(http_request(
                "GET",
                "/api/transactions",
                json!({}),
                Some(&viewer_cookie),
            ))
            .await
            .unwrap();
        assert_eq!(readable.status(), StatusCode::OK);
        assert!(response_json_value(readable).await.is_array());
    }

    #[tokio::test]
    async fn every_private_read_and_action_rejects_missing_session() {
        let temp = tempfile::tempdir().unwrap();
        let app = build_router(test_state(temp.path().to_owned()));
        for (method, path) in [
            ("GET", "/api/session"),
            ("POST", "/api/logout"),
            ("GET", "/api/users"),
            ("GET", "/api/login-audit"),
            ("GET", "/api/settings/protect/alarm"),
            ("DELETE", "/api/settings/protect/alarm"),
            ("POST", "/api/settings/protect/alarm/test"),
            ("GET", "/api/settings/deep-link"),
            ("GET", "/api/settings/protect/motion-webhook"),
            ("DELETE", "/api/settings/protect/motion-webhook"),
            ("GET", "/api/settings/thumbnail-storage"),
            ("POST", "/api/settings/thumbnail-storage/maintenance"),
            ("GET", "/oauth/square/start"),
            ("GET", "/api/settings/square/oauth-app"),
            ("DELETE", "/api/settings/square/oauth-switch"),
            ("GET", "/api/health/protect"),
            ("GET", "/api/cameras"),
            ("GET", "/api/health/square"),
            ("POST", "/api/settings/square/webhook/register"),
            ("GET", "/api/locations"),
            ("GET", "/api/pos-devices"),
            ("GET", "/api/camera-preview/abc123"),
            ("GET", "/api/camera-mapping"),
            ("GET", "/api/dashboard"),
            ("GET", "/api/motion-alerts"),
            ("GET", "/api/transactions/export.csv"),
            ("GET", "/api/transactions"),
            ("GET", "/api/thumbnails/PAY_1"),
            ("POST", "/api/sync"),
        ] {
            let response = app
                .clone()
                .oneshot(http_request(method, path, json!({}), None))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {path}"
            );
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                "private, no-store"
            );
        }
    }

    #[tokio::test]
    async fn browser_assets_revalidate_on_normal_and_conditional_requests() {
        let temp = tempfile::tempdir().unwrap();
        let app = build_router(test_state(temp.path().to_owned()));
        for path in ["/", "/app.js?v=2", "/startup.js?v=2", "/style.css?v=2"] {
            let response = app
                .clone()
                .oneshot(http_request("GET", path, json!({}), None))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                "no-cache",
                "{path}"
            );
            let etag = response.headers()[header::ETAG].clone();
            let mut request = http_request("GET", path, json!({}), None);
            request.headers_mut().insert(header::IF_NONE_MATCH, etag);
            let cached = app.clone().oneshot(request).await.unwrap();
            assert_eq!(cached.status(), StatusCode::NOT_MODIFIED, "{path}");
            assert_eq!(
                cached.headers()[header::CACHE_CONTROL],
                "no-cache",
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn security_headers_cover_static_api_and_missing_responses() {
        let temp = tempfile::tempdir().unwrap();
        let app = build_router(test_state(temp.path().to_owned()));
        for path in ["/", "/api/status", "/missing"] {
            let response = app
                .clone()
                .oneshot(http_request("GET", path, json!({}), None))
                .await
                .unwrap();
            for name in [
                "content-security-policy",
                "cross-origin-resource-policy",
                "permissions-policy",
                "referrer-policy",
                "x-content-type-options",
                "x-frame-options",
                "x-permitted-cross-domain-policies",
            ] {
                assert!(response.headers().contains_key(name), "{path}: {name}");
            }
            assert_eq!(response.headers()["x-frame-options"], "DENY");
        }
    }

    #[tokio::test]
    async fn setup_validates_secret_password_and_single_use_state() {
        let temp = tempfile::tempdir().unwrap();
        let app = build_router(test_state(temp.path().to_owned()));
        for (password, secret, expected) in [
            (
                "short",
                TEST_BOOTSTRAP_SECRET,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                ADMIN_PASSWORD,
                "wrong-bootstrap-secret-that-is-long-enough",
                StatusCode::FORBIDDEN,
            ),
        ] {
            let response = app
                .clone()
                .oneshot(http_request(
                    "POST",
                    "/api/setup",
                    json!({"password": password, "bootstrap_secret": secret}),
                    None,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }
        let setup = app
            .clone()
            .oneshot(http_request(
                "POST",
                "/api/setup",
                json!({"password": ADMIN_PASSWORD, "bootstrap_secret": TEST_BOOTSTRAP_SECRET}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(setup.status(), StatusCode::OK);
        let repeated = app
            .oneshot(http_request(
                "POST",
                "/api/setup",
                json!({"password": ADMIN_PASSWORD, "bootstrap_secret": TEST_BOOTSTRAP_SECRET}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(repeated.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn direct_session_logout_invalidates_only_current_cookie() {
        let temp = tempfile::tempdir().unwrap();
        let (state, cookie) = authenticated_state(temp.path().to_owned());
        let app = build_router(state);
        let session = app
            .clone()
            .oneshot(http_request(
                "GET",
                "/api/session",
                json!({}),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(session.status(), StatusCode::OK);
        assert_eq!(
            response_json_value(session).await["user"]["role"],
            ROLE_ADMIN
        );
        let logout = app
            .clone()
            .oneshot(http_request(
                "POST",
                "/api/logout",
                json!({}),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::OK);
        assert!(
            logout.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
        let expired = app
            .oneshot(http_request(
                "GET",
                "/api/session",
                json!({}),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(expired.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_user_routes_create_list_reset_and_never_return_passwords() {
        let temp = tempfile::tempdir().unwrap();
        let (state, cookie) = authenticated_state(temp.path().to_owned());
        let app = build_router(state);
        let created = app
            .clone()
            .oneshot(http_request(
                "POST",
                "/api/users",
                json!({"username": "audit.viewer", "password": "viewer-password", "role": "viewer"}),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let created_body = response_json_value(created).await;
        let user_id = created_body["user"]["id"].as_i64().unwrap();
        assert!(!created_body.to_string().contains("viewer-password"));
        let listed = app
            .clone()
            .oneshot(http_request("GET", "/api/users", json!({}), Some(&cookie)))
            .await
            .unwrap();
        assert_eq!(listed.status(), StatusCode::OK);
        let listed_body = response_json_value(listed).await;
        assert_eq!(listed_body["users"].as_array().unwrap().len(), 2);
        assert!(!listed_body.to_string().contains("password"));
        let reset = app
            .oneshot(http_request(
                "PUT",
                &format!("/api/users/{user_id}/password"),
                json!({"password": "replacement-password"}),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(reset.status(), StatusCode::OK);
        assert!(
            !response_json_value(reset)
                .await
                .to_string()
                .contains("replacement-password")
        );
    }

    #[tokio::test]
    async fn unconfigured_health_dashboard_and_settings_are_explicit() {
        let temp = tempfile::tempdir().unwrap();
        let (state, cookie) = authenticated_state(temp.path().to_owned());
        let app = build_router(state);
        for path in ["/api/health/protect", "/api/health/square"] {
            let response = app
                .clone()
                .oneshot(http_request("GET", path, json!({}), Some(&cookie)))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response_json_value(response).await;
            assert_eq!(body["configured"], false);
            assert_eq!(body["ok"], false);
            assert_eq!(body["detail"], "Not configured");
        }
        let dashboard = app
            .clone()
            .oneshot(http_request(
                "GET",
                "/api/dashboard",
                json!({}),
                Some(&cookie),
            ))
            .await
            .unwrap();
        let body = response_json_value(dashboard).await;
        assert_eq!(body["protect"]["configured"], false);
        assert_eq!(body["square"]["configured"], false);
        assert!(body.get("webhook").is_some());
        assert!(body.get("motion").is_some());
        assert!(body.get("queues").is_some());

        let storage = app
            .oneshot(http_request(
                "GET",
                "/api/settings/thumbnail-storage",
                json!({}),
                Some(&cookie),
            ))
            .await
            .unwrap();
        let body = response_json_value(storage).await;
        assert_eq!(body["jpeg_quality"], 72);
        assert_eq!(body["max_dimension"], 960);
        assert_eq!(body["usage"]["active_count"], 0);
    }

    #[tokio::test]
    async fn deep_link_settings_roundtrip_and_invalid_template_preserves_value() {
        let temp = tempfile::tempdir().unwrap();
        let (state, cookie) = authenticated_state(temp.path().to_owned());
        let app = build_router(state);
        let initial = app
            .clone()
            .oneshot(http_request(
                "GET",
                "/api/settings/deep-link",
                json!({}),
                Some(&cookie),
            ))
            .await
            .unwrap();
        let initial = response_json_value(initial).await;
        assert_eq!(initial["template"], "");
        assert_eq!(initial["default_template"], DEFAULT_DEEP_LINK_TEMPLATE);
        let custom = "https://{host}/protect/{camera_id}/timeline?start={ts_ms}";
        let saved = app
            .clone()
            .oneshot(http_request(
                "PUT",
                "/api/settings/deep-link",
                json!({"template": format!("  {custom}  ")}),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(saved.status(), StatusCode::OK);
        assert_eq!(response_json_value(saved).await["template"], custom);
        let invalid = app
            .clone()
            .oneshot(http_request(
                "PUT",
                "/api/settings/deep-link",
                json!({"template": "javascript:{host}/{camera_id}/{ts_ms}"}),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let current = app
            .oneshot(http_request(
                "GET",
                "/api/settings/deep-link",
                json!({}),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(response_json_value(current).await["template"], custom);
    }

    #[tokio::test]
    async fn transaction_query_note_and_export_hit_the_native_store() {
        let temp = tempfile::tempdir().unwrap();
        let (state, cookie) = authenticated_state(temp.path().to_owned());
        state
            .store
            .set_setting("protect.host", "protect.lan", false)
            .unwrap();
        state
            .store
            .replace_camera_mappings(&[CameraMappingEntry {
                location_id: "=LOC".into(),
                device_id: String::new(),
                device_name: String::new(),
                camera_id: "abc123".into(),
                camera_name: "Counter".into(),
            }])
            .unwrap();
        state
            .store
            .upsert_payment(&PaymentFacts {
                id: "=PAY_FORMULA".into(),
                created_at: "2027-01-15T08:00:00.000Z".into(),
                ts_ms: 1_800_000_000_000,
                updated_at: "2027-01-15T08:00:00.000Z".into(),
                updated_ts_ms: 1_800_000_000_000,
                amount: 99,
                currency: "USD".into(),
                status: "COMPLETED".into(),
                location_id: "=LOC".into(),
                card_last4: "@4242".into(),
                ..PaymentFacts::default()
            })
            .unwrap();
        let app = build_router(state);
        let query = app
            .clone()
            .oneshot(http_request(
                "POST",
                "/api/transactions",
                json!({"limit": 50, "offset": 0, "q": "PAY_FORMULA", "status": "COMPLETED"}),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(query.status(), StatusCode::OK);
        let payload = response_json_value(query).await;
        assert_eq!(payload.as_array().unwrap().len(), 1);
        assert!(
            payload[0]["deep_link"]
                .as_str()
                .unwrap()
                .starts_with("https://protect.lan/")
        );
        let note = app
            .clone()
            .oneshot(http_request(
                "PUT",
                "/api/transactions/=PAY_FORMULA/note",
                json!({"note": "=review this", "revision": 0}),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(note.status(), StatusCode::OK);
        assert_eq!(response_json_value(note).await["note_revision"], 1);
        let export = app
            .oneshot(http_request(
                "GET",
                "/api/transactions/export.csv",
                json!({}),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(export.status(), StatusCode::OK);
        assert!(
            export.headers()[header::CONTENT_DISPOSITION]
                .to_str()
                .unwrap()
                .contains("square-protect-transactions.csv")
        );
        let csv = String::from_utf8(response_bytes(export).await).unwrap();
        assert!(csv.contains("'=PAY_FORMULA"));
        assert!(csv.contains("'@4242"));
        assert!(csv.contains("'=review this"));
        assert!(!csv.contains("raw"));
    }

    fn seed_square_account(state: &AppState) {
        state
            .store
            .update_settings(
                &[
                    ("square.access_token", "test-old-access", true),
                    ("square.environment", "sandbox", false),
                    ("square.merchant_id", "MERCHANT_OLD", false),
                    ("square.webhook_signature_key", "test-old-key", true),
                    ("square.webhook_url", "https://example.com/old-hook", false),
                    ("square.webhook_subscription_id", "SUB_OLD", false),
                ],
                &[],
            )
            .unwrap();
        state
            .store
            .replace_camera_mappings(&[CameraMappingEntry {
                location_id: "LOC_OLD".into(),
                device_id: String::new(),
                device_name: String::new(),
                camera_id: "cam1aaaaaaaaaaaaaaaaaaaa".into(),
                camera_name: "Test camera".into(),
            }])
            .unwrap();
        state
            .store
            .upsert_payment(
                &crate::clients::parse_payment(&json!({
                    "id": "PAY_OLD", "created_at": "2026-01-01T00:00:00Z",
                    "updated_at": "2026-01-01T00:00:00Z", "status": "COMPLETED",
                    "amount_money": {"amount": 100, "currency": "USD"}, "location_id": "LOC_OLD",
                }))
                .unwrap(),
            )
            .unwrap();
        state
            .store
            .record_webhook_receipt(&"c".repeat(64), "payment.created", now_millis(), None)
            .unwrap();
        std::fs::write(state.store.thumbnail_dir().join("old.jpg"), b"old image").unwrap();
    }

    fn stage_square_oauth_switch(state: &AppState) {
        state
            .store
            .update_settings(
                &[
                    ("square.oauth_pending_access_token", "test-new-access", true),
                    (
                        "square.oauth_pending_refresh_token",
                        "test-new-refresh",
                        true,
                    ),
                    (
                        "square.oauth_pending_expires_at",
                        "2027-01-01T00:00:00Z",
                        false,
                    ),
                    ("square.oauth_pending_merchant_id", "MERCHANT_NEW", false),
                    ("square.oauth_pending_environment", "production", false),
                    (
                        "square.oauth_pending_created_at_ms",
                        &now_millis().to_string(),
                        false,
                    ),
                ],
                &[],
            )
            .unwrap();
    }

    fn square_settings_body() -> SquareSettingsBody {
        serde_json::from_value(json!({
            "access_token": "test-new-access", "environment": "production",
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn square_rejects_invalid_webhook_url_before_credentials_or_account_changes() {
        let temp = tempfile::tempdir().unwrap();
        let (state, cookie) = authenticated_state(temp.path().to_path_buf());
        seed_square_account(&state);
        let response = build_router(state.clone()).oneshot(http_request(
            "PUT", "/api/settings/square", json!({
                // Invalid credentials also keep this test offline if validation regresses.
                "access_token": "\n", "environment": "production",
                "webhook_signature_key": "test-new-key", "webhook_url": "http://example.com/hook",
                "confirm_account_switch": true,
            }), Some(&cookie),
        )).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = response_json_value(response).await;
        assert!(
            body["detail"]
                .as_str()
                .unwrap()
                .starts_with("Notification URL")
        );
        assert!(state.store.get_transaction("PAY_OLD").unwrap().is_some());
        assert_eq!(state.store.get_camera_mappings().unwrap().len(), 1);
        assert_eq!(
            state
                .store
                .get_setting("square.access_token")
                .unwrap()
                .as_deref(),
            Some("test-old-access")
        );
        assert!(state.store.thumbnail_dir().join("old.jpg").exists());
    }

    #[tokio::test]
    async fn square_manual_switch_confirms_environment_and_replaces_account_configuration() {
        for (merchant, replace_webhook, fail_cleanup) in [
            ("MERCHANT_NEW", false, true),
            ("MERCHANT_NEW", true, false),
            ("MERCHANT_OLD", false, false),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let state = test_state(temp.path().to_path_buf());
            seed_square_account(&state);
            let error = save_verified_square_account(
                &state,
                square_settings_body(),
                vec![],
                merchant.into(),
            )
            .unwrap_err();
            let response = error.into_response();
            assert_eq!(response.status(), StatusCode::CONFLICT);
            let challenge = response_json_value(response).await;
            let token = challenge["detail"]["confirmation_token"].as_str().unwrap();
            assert!(state.store.get_transaction("PAY_OLD").unwrap().is_some());
            if merchant == "MERCHANT_NEW" {
                let mut wrong_environment = square_settings_body();
                wrong_environment.environment = "sandbox".into();
                wrong_environment.confirm_account_switch = true;
                wrong_environment.account_switch_confirmation_token = token.into();
                assert!(matches!(
                    save_verified_square_account(
                        &state,
                        wrong_environment,
                        vec![],
                        merchant.into(),
                    ),
                    Err(AppError::Conflict(_))
                ));
            }
            if fail_cleanup {
                std::fs::rename(
                    state.store.thumbnail_dir(),
                    temp.path().join("saved-thumbnails"),
                )
                .unwrap();
                std::fs::write(state.store.thumbnail_dir(), b"not a directory").unwrap();
            }
            let mut body = square_settings_body();
            body.confirm_account_switch = true;
            body.account_switch_confirmation_token = token.into();
            if replace_webhook {
                body.webhook_signature_key = "test-new-key".into();
                body.webhook_url = "https://example.com/new-hook".into();
            }
            let response =
                save_verified_square_account(&state, body, vec![], merchant.into()).unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let saved = response_json_value(response).await;
            assert_eq!(saved["account_switched"], true);
            assert_eq!(saved["evidence_cleanup_pending"], fail_cleanup);
            assert_eq!(saved["webhook_configured"], replace_webhook);
            assert!(state.store.get_transaction("PAY_OLD").unwrap().is_none());
            assert!(state.store.get_camera_mappings().unwrap().is_empty());
            assert_eq!(
                state
                    .store
                    .get_setting("square.access_token")
                    .unwrap()
                    .as_deref(),
                Some("test-new-access")
            );
            assert_eq!(
                state
                    .store
                    .get_setting("square.environment")
                    .unwrap()
                    .as_deref(),
                Some("production")
            );
            assert_eq!(
                state
                    .store
                    .get_setting("square.webhook_signature_key")
                    .unwrap()
                    .as_deref(),
                replace_webhook.then_some("test-new-key")
            );
            assert_eq!(
                state
                    .store
                    .get_setting("square.webhook_url")
                    .unwrap()
                    .as_deref(),
                replace_webhook.then_some("https://example.com/new-hook")
            );
            assert!(
                state
                    .store
                    .get_setting("square.webhook_subscription_id")
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                state.store.webhook_metrics().unwrap()["accepted_payment_count"],
                0
            );
            assert_eq!(
                state.store.orphan_thumbnail_cleanup_pending().unwrap(),
                fail_cleanup
            );
        }
    }

    #[tokio::test]
    async fn square_oauth_switch_database_failure_keeps_old_account_and_pending_authorization() {
        let temp = tempfile::tempdir().unwrap();
        let (state, cookie) = authenticated_state(temp.path().to_path_buf());
        seed_square_account(&state);
        stage_square_oauth_switch(&state);
        let connection = rusqlite::Connection::open(temp.path().join("spi.db")).unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER fail_account_save BEFORE INSERT ON settings \
             WHEN NEW.key='square.access_token' \
             BEGIN SELECT RAISE(ABORT, 'injected database failure'); END;",
            )
            .unwrap();
        let app = build_router(state.clone());
        let response = app
            .clone()
            .oneshot(http_request(
                "POST",
                "/api/settings/square/oauth-switch/confirm",
                json!({}),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(state.store.get_transaction("PAY_OLD").unwrap().is_some());
        assert_eq!(state.store.get_camera_mappings().unwrap().len(), 1);
        assert_eq!(
            state
                .store
                .get_setting("square.access_token")
                .unwrap()
                .as_deref(),
            Some("test-old-access")
        );
        assert_eq!(
            state
                .store
                .get_setting("square.webhook_signature_key")
                .unwrap()
                .as_deref(),
            Some("test-old-key")
        );
        assert_eq!(
            state
                .store
                .get_setting("square.oauth_pending_access_token")
                .unwrap()
                .as_deref(),
            Some("test-new-access")
        );
        assert!(state.store.thumbnail_dir().join("old.jpg").exists());
        connection
            .execute_batch("DROP TRIGGER fail_account_save")
            .unwrap();
        let response = app
            .oneshot(http_request(
                "POST",
                "/api/settings/square/oauth-switch/confirm",
                json!({}),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response_json_value(response).await["evidence_cleanup_pending"],
            false
        );
        assert!(state.store.get_transaction("PAY_OLD").unwrap().is_none());
        assert!(!state.store.thumbnail_dir().join("old.jpg").exists());
    }

    #[tokio::test]
    async fn square_oauth_switch_clears_webhooks_and_retries_cleanup_without_polling() {
        let temp = tempfile::tempdir().unwrap();
        let (state, cookie) = authenticated_state(temp.path().to_path_buf());
        seed_square_account(&state);
        stage_square_oauth_switch(&state);
        let displaced = temp.path().join("saved-thumbnails");
        std::fs::rename(state.store.thumbnail_dir(), &displaced).unwrap();
        std::fs::write(state.store.thumbnail_dir(), b"not a directory").unwrap();
        let response = build_router(state.clone())
            .oneshot(http_request(
                "POST",
                "/api/settings/square/oauth-switch/confirm",
                json!({}),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response_json_value(response).await["evidence_cleanup_pending"],
            true
        );
        assert!(state.store.get_transaction("PAY_OLD").unwrap().is_none());
        assert!(state.store.get_camera_mappings().unwrap().is_empty());
        assert_eq!(
            state
                .store
                .get_setting("square.access_token")
                .unwrap()
                .as_deref(),
            Some("test-new-access")
        );
        assert_eq!(
            state
                .store
                .get_setting("square.environment")
                .unwrap()
                .as_deref(),
            Some("production")
        );
        for key in [
            "square.webhook_signature_key",
            "square.webhook_url",
            "square.webhook_subscription_id",
            "square.oauth_pending_access_token",
        ] {
            assert!(state.store.get_setting(key).unwrap().is_none(), "{key}");
        }
        assert_eq!(
            state.store.webhook_metrics().unwrap()["accepted_payment_count"],
            0
        );
        assert!(state.config.poll_interval.is_none());
        let scheduler = tokio::spawn(
            state
                .clone()
                .run_maintenance_scheduler(Duration::from_millis(20)),
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if state.maintenance.read().await["state"] == "complete" {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(state.store.orphan_thumbnail_cleanup_pending().unwrap());
        std::fs::remove_file(state.store.thumbnail_dir()).unwrap();
        std::fs::rename(&displaced, state.store.thumbnail_dir()).unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while state.store.orphan_thumbnail_cleanup_pending().unwrap()
                || state.maintenance_queue.lock().await.active
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        scheduler.abort();
        let _ = scheduler.await;
        assert!(!state.store.thumbnail_dir().join("old.jpg").exists());
    }

    #[tokio::test]
    async fn square_webhook_fails_closed_before_configuration_and_signature() {
        let temp = tempfile::tempdir().unwrap();
        let state = test_state(temp.path().to_owned());
        let app = build_router(state.clone());
        let unconfigured = app
            .clone()
            .oneshot(http_request(
                "POST",
                "/webhooks/square",
                json!({"type": "payment.updated"}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(unconfigured.status(), StatusCode::FORBIDDEN);
        state
            .store
            .update_settings(
                &[
                    ("square.webhook_signature_key", "webhook-key", true),
                    (
                        "square.webhook_url",
                        "https://example.test/webhooks/square",
                        false,
                    ),
                    ("square.merchant_id", "MERCHANT_1", false),
                ],
                &[],
            )
            .unwrap();
        let unsigned = app
            .oneshot(http_request(
                "POST",
                "/webhooks/square",
                json!({"merchant_id": "MERCHANT_1", "type": "payment.updated"}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(unsigned.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_throttle_is_ip_bound_even_when_usernames_change() {
        let temp = tempfile::tempdir().unwrap();
        let app = build_router(test_state(temp.path().to_owned()));
        let setup = app
            .clone()
            .oneshot(http_request(
                "POST",
                "/api/setup",
                json!({
                    "password": ADMIN_PASSWORD,
                    "bootstrap_secret": TEST_BOOTSTRAP_SECRET,
                }),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(setup.status(), StatusCode::OK);

        for attempt in 0..LOGIN_MAX_FAILURES {
            let response = app
                .clone()
                .oneshot(http_request(
                    "POST",
                    "/api/login",
                    json!({
                        "username": format!("missing-{attempt}"),
                        "password": "wrong-password",
                    }),
                    None,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let blocked = app
            .oneshot(http_request(
                "POST",
                "/api/login",
                json!({"username": "admin", "password": ADMIN_PASSWORD}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn plaintext_remote_bootstrap_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let mut state = test_state(temp.path().to_owned());
        state.config.bind_host = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let app = build_router(state);
        let mut request = http_request(
            "POST",
            "/api/setup",
            json!({
                "password": ADMIN_PASSWORD,
                "bootstrap_secret": TEST_BOOTSTRAP_SECRET,
            }),
            None,
        );
        request.extensions_mut().insert(ConnectInfo(
            "10.0.7.42:41000".parse::<SocketAddr>().unwrap(),
        ));
        *request.headers_mut().get_mut(header::HOST).unwrap() =
            HeaderValue::from_static("10.23.45.67:8000");
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response_json_value(response).await["detail"]["code"],
            "bootstrap_tls_not_configured"
        );
    }
}
