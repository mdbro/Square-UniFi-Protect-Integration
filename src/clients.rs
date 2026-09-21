use std::{sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use reqwest::{Client, Method, StatusCode, header};
use serde_json::{Value, json};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use url::Url;

use crate::{AppError, AppResult, models::PaymentFacts, store::validate_camera_id};

pub const SQUARE_VERSION: &str = "2025-01-23";
const SQUARE_READ_SCOPES: [&str; 2] = ["MERCHANT_PROFILE_READ", "PAYMENTS_READ"];
const SQUARE_PRODUCTION_URL: &str = "https://connect.squareup.com";
const SQUARE_SANDBOX_URL: &str = "https://connect.squareupsandbox.com";

#[derive(Clone)]
pub struct SquareClient {
    client: Client,
    base_url: String,
    pub environment: String,
}

impl SquareClient {
    pub fn new(access_token: &str, environment: &str) -> AppResult<Self> {
        if access_token.is_empty() || access_token.len() > 16_384 || has_control(access_token) {
            return Err(AppError::Unprocessable(
                "Invalid Square access token".into(),
            ));
        }
        let base_url = square_base_url(environment)?;
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!("Bearer {access_token}"))
                .map_err(AppError::internal)?,
        );
        headers.insert(
            "square-version",
            header::HeaderValue::from_static(SQUARE_VERSION),
        );
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );
        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(AppError::internal)?;
        Ok(Self {
            client,
            base_url: base_url.to_owned(),
            environment: environment.to_owned(),
        })
    }

    async fn request_json(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
    ) -> AppResult<Value> {
        // Keep this boundary independent of the token's permissions. Personal
        // access tokens can write to Square, but this application cannot.
        if method != Method::GET
            || !matches!(path, "/v2/locations" | "/v2/merchants/me" | "/v2/payments")
        {
            return Err(AppError::Forbidden(
                "Square access is read-only; this request is not permitted".into(),
            ));
        }
        let url = format!("{}{path}", self.base_url);
        let mut attempt = 0_u32;
        loop {
            let response = match self.client.get(&url).query(query).send().await {
                Ok(response) => response,
                Err(error) if attempt < 3 => {
                    tracing::warn!(%error, %path, "Square request had a network error; retrying");
                    tokio::time::sleep(retry_delay(attempt, None)).await;
                    attempt += 1;
                    continue;
                }
                Err(error) => {
                    return Err(AppError::Upstream(format!(
                        "Network error while contacting Square: {error}"
                    )));
                }
            };
            let status = response.status();
            if attempt < 3 && matches!(status.as_u16(), 429 | 500 | 502 | 503 | 504) {
                tokio::time::sleep(retry_delay(attempt, response.headers().get("retry-after")))
                    .await;
                attempt += 1;
                continue;
            }
            if status == StatusCode::UNAUTHORIZED {
                return Err(AppError::Unauthorized(
                    "Square rejected the access token".into(),
                ));
            }
            if status == StatusCode::FORBIDDEN {
                return Err(AppError::Forbidden(
                    "Square rejected the token's permissions".into(),
                ));
            }
            if !status.is_success() {
                return Err(AppError::Upstream(format!(
                    "Square request {path} failed (HTTP {})",
                    status.as_u16()
                )));
            }
            return response
                .json::<Value>()
                .await
                .map_err(|_| AppError::Upstream("Square returned a non-JSON response".into()));
        }
    }

    pub async fn list_locations(&self) -> AppResult<Vec<Value>> {
        let payload = self.request_json(Method::GET, "/v2/locations", &[]).await?;
        object_array(&payload, "locations")?
            .iter()
            .map(|location| {
                let id = required_text(location, "id", "Square location id")?;
                Ok(json!({
                    "id": id,
                    "name": optional_text(location, "name", "Square location name")?,
                    "status": optional_text(location, "status", "Square location status")?,
                }))
            })
            .collect()
    }

    pub async fn merchant_id(&self) -> AppResult<String> {
        let payload = self
            .request_json(Method::GET, "/v2/merchants/me", &[])
            .await?;
        let merchant = payload
            .get("merchant")
            .and_then(Value::as_object)
            .ok_or_else(|| AppError::Upstream("Square returned an invalid merchant".into()))?;
        merchant
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                AppError::Upstream("Square did not return the access token's merchant id".into())
            })
    }

    pub async fn payment_page(
        &self,
        location_id: Option<&str>,
        updated_at_begin_time: Option<&str>,
        cursor: Option<&str>,
        limit: usize,
    ) -> AppResult<(Vec<Value>, Option<String>)> {
        let mut query = vec![
            ("sort_field", "UPDATED_AT".into()),
            ("sort_order", "ASC".into()),
            ("limit", limit.clamp(1, 100).to_string()),
        ];
        if let Some(location_id) = location_id {
            query.push(("location_id", location_id.to_owned()));
        }
        if let Some(begin) = updated_at_begin_time {
            query.push(("updated_at_begin_time", begin.to_owned()));
        }
        if let Some(value) = cursor {
            query.push(("cursor", value.to_owned()));
        }
        let payload = self
            .request_json(Method::GET, "/v2/payments", &query)
            .await?;
        let page = object_array(&payload, "payments")?.to_vec();
        let cursor = match payload.get("cursor") {
            None | Some(Value::Null) => None,
            Some(Value::String(value)) if value.is_empty() => None,
            Some(Value::String(value)) if value.len() <= 4096 && !has_control(value) => {
                Some(value.clone())
            }
            _ => {
                return Err(AppError::Upstream(
                    "Square returned an invalid pagination cursor".into(),
                ));
            }
        };
        Ok((page, cursor))
    }
}

#[derive(Clone)]
pub struct ProtectClient {
    base_url: String,
    username: String,
    password: String,
    api_key: Option<String>,
    session_client: Client,
    integration_client: Client,
    csrf_token: Arc<Mutex<Option<String>>>,
}

impl ProtectClient {
    pub fn new(
        host: &str,
        username: &str,
        password: &str,
        verify_ssl: bool,
        api_key: Option<&str>,
    ) -> AppResult<Self> {
        let host = validate_protect_host(host)?;
        if api_key.is_some_and(|value| value.len() > 512 || has_control(value)) {
            return Err(AppError::Unprocessable(
                "Invalid UniFi Protect API key".into(),
            ));
        }
        let session_client = Client::builder()
            .cookie_store(true)
            .tls_danger_accept_invalid_certs(!verify_ssl)
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(AppError::internal)?;
        let integration_client = Client::builder()
            .tls_danger_accept_invalid_certs(!verify_ssl)
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(AppError::internal)?;
        Ok(Self {
            base_url: format!("https://{host}"),
            username: username.to_owned(),
            password: password.to_owned(),
            api_key: api_key
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
            session_client,
            integration_client,
            csrf_token: Arc::new(Mutex::new(None)),
        })
    }

    async fn login(&self) -> AppResult<()> {
        let url = format!("{}/api/auth/login", self.base_url);
        for attempt in 0..=3 {
            let response = self
                .session_client
                .post(&url)
                .json(&json!({
                    "username": self.username,
                    "password": self.password,
                    "rememberMe": true,
                }))
                .send()
                .await
                .map_err(|error| {
                    AppError::Upstream(format!(
                        "Network error while contacting UniFi Protect: {error}"
                    ))
                })?;
            if response.status() == StatusCode::TOO_MANY_REQUESTS && attempt < 3 {
                tokio::time::sleep(retry_delay(attempt, response.headers().get("retry-after")))
                    .await;
                continue;
            }
            if matches!(
                response.status(),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
            ) {
                return Err(AppError::Unauthorized(
                    "UniFi Protect rejected the credentials".into(),
                ));
            }
            if !response.status().is_success() {
                return Err(AppError::Upstream(format!(
                    "UniFi Protect login failed (HTTP {})",
                    response.status().as_u16()
                )));
            }
            let csrf = response
                .headers()
                .get("x-csrf-token")
                .or_else(|| response.headers().get("x-updated-csrf-token"))
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned);
            *self.csrf_token.lock().await = csrf;
            return Ok(());
        }
        unreachable!()
    }

    async fn session_request(&self, method: Method, path: &str) -> AppResult<reqwest::Response> {
        if self.csrf_token.lock().await.is_none() {
            self.login().await?;
        }
        for attempt in 0..=1 {
            let mut request = self
                .session_client
                .request(method.clone(), format!("{}{path}", self.base_url));
            if let Some(csrf) = self.csrf_token.lock().await.clone() {
                request = request.header("x-csrf-token", csrf);
            }
            let response = request.send().await.map_err(|error| {
                AppError::Upstream(format!(
                    "Network error while contacting UniFi Protect: {error}"
                ))
            })?;
            if response.status() == StatusCode::UNAUTHORIZED && attempt == 0 {
                self.login().await?;
                continue;
            }
            return Ok(response);
        }
        unreachable!()
    }

    pub async fn cameras_with_console_identity(&self) -> AppResult<(Vec<Value>, Option<String>)> {
        let response = self
            .session_request(Method::GET, "/proxy/protect/api/bootstrap")
            .await?;
        require_success(&response, "UniFi Protect camera request")?;
        let payload: Value = response
            .json()
            .await
            .map_err(|_| AppError::Upstream("UniFi Protect camera response was not JSON".into()))?;
        let cameras = payload
            .get("cameras")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                AppError::Upstream("UniFi Protect camera response was invalid".into())
            })?;
        let normalized = cameras
            .iter()
            .map(|camera| {
                let id = required_text(camera, "id", "Protect camera id")?;
                validate_camera_id(&id)?;
                let name = optional_text(camera, "name", "Protect camera name")?;
                let market_name = optional_text(camera, "marketName", "Protect camera market name")?;
                let state = optional_text(camera, "state", "Protect camera state")?;
                Ok(json!({
                    "id": id,
                    "name": if name.is_empty() { if market_name.is_empty() { id.clone() } else { market_name } } else { name },
                    "state": state,
                }))
            })
            .collect::<AppResult<Vec<_>>>()?;
        let console_id = ["id", "mac"].iter().find_map(|field| {
            payload
                .pointer(&format!("/nvr/{field}"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty() && value.len() <= 256 && !has_control(value))
                .map(ToOwned::to_owned)
        });
        Ok((normalized, console_id))
    }

    pub async fn cameras(&self) -> AppResult<Vec<Value>> {
        Ok(self.cameras_with_console_identity().await?.0)
    }

    pub async fn snapshot(&self, camera_id: &str, ts_ms: Option<i64>) -> AppResult<Vec<u8>> {
        validate_camera_id(camera_id)?;
        let path = if let Some(ts_ms) = ts_ms {
            format!("/proxy/protect/api/cameras/{camera_id}/recording-snapshot?ts={ts_ms}")
        } else {
            format!("/proxy/protect/api/cameras/{camera_id}/snapshot?w=640")
        };
        let response = self.session_request(Method::GET, &path).await?;
        if ts_ms.is_some() && response.status() == StatusCode::NOT_FOUND {
            return Err(AppError::Upstream(format!(
                "No recording available for camera {camera_id} at the requested timestamp"
            )));
        }
        require_success(&response, "UniFi Protect snapshot")?;
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if !content_type.is_empty()
            && !matches!(
                content_type.as_str(),
                "image/jpeg"
                    | "image/jpg"
                    | "image/pjpeg"
                    | "application/octet-stream"
                    | "binary/octet-stream"
            )
        {
            return Err(AppError::Upstream(
                "UniFi Protect snapshot response was not a JPEG".into(),
            ));
        }
        let bytes = response.bytes().await.map_err(AppError::internal)?.to_vec();
        if !is_complete_jpeg(&bytes) {
            return Err(AppError::Upstream(
                "UniFi Protect snapshot response contained invalid JPEG data".into(),
            ));
        }
        Ok(bytes)
    }

    async fn integration_request(
        &self,
        method: Method,
        path: &str,
    ) -> AppResult<reqwest::Response> {
        let key = self.api_key.as_deref().ok_or_else(|| {
            AppError::Unauthorized("UniFi Protect API key is not configured".into())
        })?;
        let response = self
            .integration_client
            .request(method, format!("{}{path}", self.base_url))
            .header("x-api-key", key)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| {
                AppError::Upstream(format!(
                    "Network error while contacting UniFi Protect: {error}"
                ))
            })?;
        if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            return Err(AppError::Unauthorized(
                "UniFi Protect rejected the API key".into(),
            ));
        }
        require_success(&response, "UniFi Protect integration request")?;
        Ok(response)
    }

    pub async fn integration_info(&self) -> AppResult<Value> {
        let response = self
            .integration_request(Method::GET, "/proxy/protect/integration/v1/meta/info")
            .await?;
        let payload: Value = response.json().await.map_err(|_| {
            AppError::Upstream("UniFi Protect integration metadata was not JSON".into())
        })?;
        if payload
            .get("applicationVersion")
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(AppError::Upstream(
                "UniFi Protect integration metadata was invalid".into(),
            ));
        }
        Ok(payload)
    }

    pub async fn trigger_alarm(&self, trigger_id: &str) -> AppResult<()> {
        let trigger_id = validate_alarm_trigger_id(trigger_id)?;
        let encoded: String = url::form_urlencoded::byte_serialize(trigger_id.as_bytes()).collect();
        // Form encoding represents spaces as '+', but this value is one URL
        // path segment where '+' is literal and spaces must be percent encoded.
        let encoded = encoded.replace('+', "%20");
        self.integration_request(
            Method::POST,
            &format!("/proxy/protect/integration/v1/alarm-manager/webhook/{encoded}"),
        )
        .await?;
        Ok(())
    }
}

pub fn square_base_url(environment: &str) -> AppResult<&'static str> {
    match environment {
        "production" => Ok(SQUARE_PRODUCTION_URL),
        "sandbox" => Ok(SQUARE_SANDBOX_URL),
        _ => Err(AppError::Unprocessable(
            "environment must be 'production' or 'sandbox'".into(),
        )),
    }
}

pub fn validate_protect_host(value: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 255
        || value.contains(['/', '\\', '@', '?', '#'])
        || value.chars().any(char::is_whitespace)
    {
        return Err(AppError::Unprocessable(
            "Protect host must be a hostname or IP address (optionally with :port), without scheme or path".into(),
        ));
    }
    let url = Url::parse(&format!("https://{value}"))
        .map_err(|_| AppError::Unprocessable("Invalid Protect host".into()))?;
    if url.host_str().is_none()
        || url.port_or_known_default().is_none()
        || url.port() == Some(0)
        || value.ends_with(':')
    {
        return Err(AppError::Unprocessable("Invalid Protect host".into()));
    }
    Ok(value.to_owned())
}

pub fn validate_alarm_trigger_id(value: &str) -> AppResult<String> {
    let value = value.trim();
    if !(1..=256).contains(&value.len()) || has_control(value) {
        return Err(AppError::Unprocessable(
            "Alarm trigger id must be 1-256 characters without control characters".into(),
        ));
    }
    Ok(value.to_owned())
}

pub fn verify_square_webhook_signature(
    signature_key: &str,
    notification_url: &str,
    body: &[u8],
    signature_header: &str,
) -> bool {
    if signature_key.is_empty() || signature_header.is_empty() {
        return false;
    }
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(signature_key.as_bytes()) else {
        return false;
    };
    mac.update(notification_url.as_bytes());
    mac.update(body);
    let expected = STANDARD.encode(mac.finalize().into_bytes());
    expected.len() == signature_header.len()
        && bool::from(expected.as_bytes().ct_eq(signature_header.as_bytes()))
}

pub fn parse_payment(payment: &Value) -> AppResult<PaymentFacts> {
    let object = payment
        .as_object()
        .ok_or_else(|| AppError::Unprocessable("Payment must be an object".into()))?;
    let amount_money = optional_object(payment, "amount_money")?;
    let total_money = optional_object(payment, "total_money")?;
    let display_money = if total_money.is_empty() {
        &amount_money
    } else {
        &total_money
    };
    let amount = display_money
        .get("amount")
        .or_else(|| amount_money.get("amount"))
        .map(|value| {
            value
                .as_i64()
                .ok_or_else(|| AppError::Unprocessable("Payment amount must be an integer".into()))
        })
        .transpose()?
        .unwrap_or(0);
    let display_currency = display_money.get("currency");
    let currency = if display_currency
        .is_none_or(|value| value.is_null() || value.as_str().is_some_and(str::is_empty))
    {
        amount_money.get("currency")
    } else {
        display_currency
    };
    let currency = match currency {
        None | Some(Value::Null) => "USD".to_owned(),
        Some(Value::String(value)) if value.is_empty() => "USD".to_owned(),
        Some(Value::String(value)) => value.clone(),
        _ => {
            return Err(AppError::Unprocessable(
                "Payment currency must be a string".into(),
            ));
        }
    };
    let refunded_amount = if object.contains_key("refunded_money") {
        let refunded = optional_object(payment, "refunded_money")?;
        let amount = refunded
            .get("amount")
            .and_then(Value::as_i64)
            .filter(|value| *value >= 0)
            .ok_or_else(|| {
                AppError::Unprocessable(
                    "Payment refunded_money.amount must be a non-negative integer".into(),
                )
            })?;
        let refund_currency = refunded
            .get("currency")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                AppError::Unprocessable("Payment refunded_money.currency is required".into())
            })?;
        if refund_currency.len() != 3
            || !refund_currency
                .bytes()
                .all(|value| value.is_ascii_alphabetic() && value.is_ascii_uppercase())
        {
            return Err(AppError::Unprocessable(
                "Payment refunded_money.currency must be an uppercase ISO currency code".into(),
            ));
        }
        if refund_currency != currency {
            return Err(AppError::Unprocessable(
                "Payment refunded_money currency does not match payment".into(),
            ));
        }
        amount
    } else {
        0
    };
    let card_details = optional_object(payment, "card_details")?;
    let card = card_details
        .get("card")
        .map(|value| {
            value.as_object().ok_or_else(|| {
                AppError::Unprocessable("Payment card_details.card must be an object".into())
            })
        })
        .transpose()?
        .cloned()
        .unwrap_or_default();
    let device = optional_object(payment, "device_details")?;
    let offline = optional_object(payment, "offline_payment_details")?;
    let server_created_at = payment_required_text(payment, "created_at", "Payment created_at")?;
    let created_at = if payment.get("is_offline_payment") == Some(&Value::Bool(true)) {
        match offline.get("client_created_at") {
            None | Some(Value::Null) => server_created_at.clone(),
            Some(Value::String(value)) if value.trim().is_empty() => server_created_at.clone(),
            Some(Value::String(value)) => value.trim().to_owned(),
            _ => {
                return Err(AppError::Unprocessable(
                    "Payment offline_payment_details.client_created_at must be a string".into(),
                ));
            }
        }
    } else {
        server_created_at.clone()
    };
    let updated_at = payment_optional_text(payment, "updated_at", "Payment updated_at")?;
    let updated_at = if updated_at.is_empty() {
        server_created_at
    } else {
        updated_at
    };
    Ok(PaymentFacts {
        id: payment_required_text(payment, "id", "Payment id")?,
        ts_ms: parse_timestamp_ms(&created_at)?,
        updated_ts_ms: parse_timestamp_ms(&updated_at)?,
        created_at,
        updated_at,
        amount,
        currency,
        refunded_amount,
        status: payment_optional_text(payment, "status", "Payment status")?,
        location_id: payment_optional_text(payment, "location_id", "Payment location_id")?,
        device_id: payment_map_text(&device, "device_id", "Payment device_details.device_id")?,
        device_name: payment_map_text(
            &device,
            "device_name",
            "Payment device_details.device_name",
        )?,
        card_last4: payment_map_text(&card, "last_4", "Payment card_details.card.last_4")?,
        receipt_url: payment_optional_text(payment, "receipt_url", "Payment receipt_url")?,
    })
}

pub fn oauth_authorize_url(environment: &str, client_id: &str, state: &str) -> AppResult<String> {
    let base = square_base_url(environment)?;
    let mut url = Url::parse(&format!("{base}/oauth2/authorize")).map_err(AppError::internal)?;
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("scope", &SQUARE_READ_SCOPES.join(" "))
        .append_pair("session", "false")
        .append_pair("state", state);
    Ok(url.into())
}

fn oauth_token_request(
    environment: &str,
    client_id: &str,
    client_secret: &str,
    code: Option<&str>,
    refresh_token: Option<&str>,
) -> AppResult<reqwest::RequestBuilder> {
    let base = square_base_url(environment)?;
    let mut body = json!({
        "client_id": client_id,
        "client_secret": client_secret,
    });
    if let Some(code) = code {
        body["grant_type"] = Value::String("authorization_code".into());
        body["code"] = Value::String(code.into());
    } else if let Some(refresh) = refresh_token {
        body["grant_type"] = Value::String("refresh_token".into());
        body["refresh_token"] = Value::String(refresh.into());
        body["scopes"] = json!(SQUARE_READ_SCOPES);
    } else {
        return Err(AppError::Unprocessable(
            "code or refresh_token is required".into(),
        ));
    }
    // This POST only obtains authentication tokens; it never changes Square
    // payments or account configuration. Do not follow redirects with secrets.
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(AppError::internal)?;
    Ok(client
        .post(format!("{base}/oauth2/token"))
        .header("Square-Version", SQUARE_VERSION)
        .json(&body))
}

pub async fn oauth_exchange(
    environment: &str,
    client_id: &str,
    client_secret: &str,
    code: Option<&str>,
    refresh_token: Option<&str>,
) -> AppResult<Value> {
    let response = oauth_token_request(environment, client_id, client_secret, code, refresh_token)?
        .send()
        .await
        .map_err(|error| {
            AppError::Upstream(format!("Network error while contacting Square: {error}"))
        })?;
    if matches!(response.status().as_u16(), 400 | 401 | 403) {
        return Err(AppError::Unauthorized(
            "Square rejected the OAuth request".into(),
        ));
    }
    require_success(&response, "Square OAuth")?;
    let payload: Value = response
        .json()
        .await
        .map_err(|_| AppError::Upstream("Square returned a non-JSON response".into()))?;
    if payload
        .get("access_token")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(AppError::Upstream(
            "Square returned an invalid OAuth response".into(),
        ));
    }
    Ok(payload)
}

fn parse_timestamp_ms(value: &str) -> AppResult<i64> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc).timestamp_millis())
        .map_err(|_| AppError::Unprocessable("Payment timestamp is invalid".into()))
}

fn object_array<'a>(payload: &'a Value, key: &str) -> AppResult<&'a [Value]> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(values)) => Ok(values),
        Some(_) => Err(AppError::Upstream(
            "Square returned an invalid response".into(),
        )),
    }
}

fn optional_object(payload: &Value, key: &str) -> AppResult<serde_json::Map<String, Value>> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(Default::default()),
        Some(Value::Object(value)) => Ok(value.clone()),
        Some(_) => Err(AppError::Unprocessable(format!(
            "Payment {key} must be an object"
        ))),
    }
}

fn required_text(payload: &Value, key: &str, label: &str) -> AppResult<String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| AppError::Upstream(format!("{label} was missing or invalid")))
}

fn optional_text(payload: &Value, key: &str, label: &str) -> AppResult<String> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(AppError::Upstream(format!("{label} was invalid"))),
    }
}

fn payment_required_text(payload: &Value, key: &str, label: &str) -> AppResult<String> {
    match payload.get(key) {
        Some(Value::String(value)) if !value.is_empty() => Ok(value.clone()),
        _ => Err(AppError::Unprocessable(format!(
            "{label} is required and must be a string"
        ))),
    }
}

fn payment_optional_text(payload: &Value, key: &str, label: &str) -> AppResult<String> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) => Ok(value.clone()),
        _ => Err(AppError::Unprocessable(format!("{label} must be a string"))),
    }
}

fn payment_map_text(
    payload: &serde_json::Map<String, Value>,
    key: &str,
    label: &str,
) -> AppResult<String> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) => Ok(value.clone()),
        _ => Err(AppError::Unprocessable(format!("{label} must be a string"))),
    }
}

fn retry_delay(attempt: u32, retry_after: Option<&header::HeaderValue>) -> Duration {
    if let Some(seconds) = retry_after
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value >= 0.0)
    {
        return Duration::from_secs_f64(seconds.min(10.0));
    }
    Duration::from_secs_f64((0.5 * 2_f64.powi(attempt as i32)).min(10.0))
}

fn require_success(response: &reqwest::Response, label: &str) -> AppResult<()> {
    if response.status().is_success() {
        Ok(())
    } else {
        Err(AppError::Upstream(format!(
            "{label} failed (HTTP {})",
            response.status().as_u16()
        )))
    }
}

fn has_control(value: &str) -> bool {
    value
        .chars()
        .any(|character| character < ' ' || character == '\u{7f}')
}

fn is_complete_jpeg(content: &[u8]) -> bool {
    if !content.starts_with(&[0xff, 0xd8]) {
        return false;
    }
    let mut position = 2;
    let mut in_scan = false;
    let mut saw_frame = false;
    let mut saw_scan = false;
    let mut saw_scan_data = false;
    while position < content.len() {
        if in_scan {
            let Some(relative) = content[position..].iter().position(|byte| *byte == 0xff) else {
                return false;
            };
            let marker_start = position + relative;
            if marker_start + 1 >= content.len() {
                return false;
            }
            if marker_start > position {
                saw_scan_data = true;
            }
            let marker = content[marker_start + 1];
            if marker == 0x00 {
                saw_scan_data = true;
                position = marker_start + 2;
                continue;
            }
            if marker == 0xff {
                position = marker_start + 1;
                continue;
            }
            if (0xd0..=0xd7).contains(&marker) {
                position = marker_start + 2;
                continue;
            }
            position = marker_start;
            in_scan = false;
            continue;
        }
        if content[position] != 0xff {
            return false;
        }
        while position < content.len() && content[position] == 0xff {
            position += 1;
        }
        if position >= content.len() {
            return false;
        }
        let marker = content[position];
        position += 1;
        if marker == 0xd9 {
            return saw_frame && saw_scan && saw_scan_data;
        }
        if marker == 0xd8 || marker == 0x00 {
            return false;
        }
        if marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        if position + 2 > content.len() {
            return false;
        }
        let length = u16::from_be_bytes([content[position], content[position + 1]]) as usize;
        if length < 2 || position + length > content.len() {
            return false;
        }
        if matches!(
            marker,
            0xc0 | 0xc1
                | 0xc2
                | 0xc3
                | 0xc5
                | 0xc6
                | 0xc7
                | 0xc9
                | 0xca
                | 0xcb
                | 0xcd
                | 0xce
                | 0xcf
        ) {
            saw_frame = true;
        }
        if marker == 0xda {
            if !saw_frame {
                return false;
            }
            saw_scan = true;
            in_scan = true;
        }
        position += length;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, http::Request, response::IntoResponse, routing::any};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::net::TcpListener;

    fn base_payment() -> Value {
        json!({
            "id": "PAY_1",
            "created_at": "2026-07-16T15:30:00.000Z",
            "updated_at": "2026-07-16T15:31:00.000Z",
            "amount_money": {"amount": 99, "currency": "USD"},
            "status": "COMPLETED",
            "location_id": "LOC_1"
        })
    }

    fn minimal_jpeg() -> Vec<u8> {
        vec![
            0xff, 0xd8, 0xff, 0xc0, 0x00, 0x0b, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11,
            0x00, 0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00, 0x01, 0x02, 0xff,
            0xd9,
        ]
    }

    async fn spawn_http(router: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        format!("http://{address}")
    }

    async fn square_with_router(router: Router) -> SquareClient {
        let mut client = SquareClient::new("sandbox-access-token", "sandbox").unwrap();
        client.base_url = spawn_http(router).await;
        client
    }

    async fn protect_with_router(router: Router, api_key: Option<&str>) -> ProtectClient {
        let mut client =
            ProtectClient::new("protect.test", "Square", "password", true, api_key).unwrap();
        client.base_url = spawn_http(router).await;
        client
    }

    #[test]
    fn square_environment_and_tokens_are_strictly_validated() {
        assert_eq!(
            square_base_url("production").unwrap(),
            "https://connect.squareup.com"
        );
        assert_eq!(
            square_base_url("sandbox").unwrap(),
            "https://connect.squareupsandbox.com"
        );
        for environment in ["", "Sandbox", "test", "production "] {
            assert!(matches!(
                square_base_url(environment),
                Err(AppError::Unprocessable(_))
            ));
        }
        for token in ["", "line\nfeed", "delete\u{7f}"] {
            assert!(matches!(
                SquareClient::new(token, "sandbox"),
                Err(AppError::Unprocessable(_))
            ));
        }
        assert!(SquareClient::new("sandbox-token", "sandbox").is_ok());
    }

    #[test]
    fn protect_host_accepts_runtime_hosts_and_rejects_url_injection() {
        for (input, expected) in [
            ("192.0.2.123", "192.0.2.123"),
            (" protect.lan ", "protect.lan"),
            ("protect.lan:7443", "protect.lan:7443"),
            ("[fd00::1234]:443", "[fd00::1234]:443"),
        ] {
            assert_eq!(validate_protect_host(input).unwrap(), expected);
        }
        for input in [
            "",
            "https://protect.lan",
            "protect.lan/path",
            "user@protect.lan",
            "protect.lan?x=1",
            "protect.lan#fragment",
            "protect .lan",
            "protect.lan:",
            "protect.lan:0",
            "protect.lan:65536",
        ] {
            assert!(
                matches!(
                    validate_protect_host(input),
                    Err(AppError::Unprocessable(_))
                ),
                "{input:?}"
            );
        }
    }

    #[test]
    fn alarm_trigger_ids_allow_admin_labels_but_reject_controls_and_bounds() {
        for value in [
            "sale",
            "Checkout Camera Sale",
            "motion/webhook:flag",
            " webhook id ",
        ] {
            assert!(!validate_alarm_trigger_id(value).unwrap().is_empty());
        }
        for value in ["", " \t ", "sale\nother", "sale\u{7f}other"] {
            assert!(matches!(
                validate_alarm_trigger_id(value),
                Err(AppError::Unprocessable(_))
            ));
        }
        assert!(matches!(
            validate_alarm_trigger_id(&"A".repeat(257)),
            Err(AppError::Unprocessable(_))
        ));
    }

    #[test]
    fn protect_api_key_validation_fails_closed() {
        assert!(ProtectClient::new("protect.lan", "Square", "password", false, None).is_ok());
        assert!(
            ProtectClient::new("protect.lan", "Square", "password", true, Some(" key ")).is_ok()
        );
        assert!(matches!(
            ProtectClient::new("protect.lan", "Square", "password", true, Some("bad\nkey")),
            Err(AppError::Unprocessable(_))
        ));
        let oversized = "x".repeat(513);
        assert!(matches!(
            ProtectClient::new("protect.lan", "Square", "password", true, Some(&oversized)),
            Err(AppError::Unprocessable(_))
        ));
    }

    #[test]
    fn square_signature_matches_reference_protocol() {
        let key = "webhook-secret";
        let url = "https://example.test/webhooks/square";
        let body = br#"{"type":"payment.updated"}"#;
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
        mac.update(url.as_bytes());
        mac.update(body);
        let signature = STANDARD.encode(mac.finalize().into_bytes());
        assert!(verify_square_webhook_signature(key, url, body, &signature));
        assert!(!verify_square_webhook_signature(
            key, url, b"changed", &signature
        ));
    }

    #[test]
    fn parses_square_payment_without_retaining_raw_buyer_data() {
        let payment = json!({
            "id": "PAY_1",
            "created_at": "2026-07-16T15:30:00.000Z",
            "updated_at": "2026-07-16T15:31:00.000Z",
            "amount_money": {"amount": 99, "currency": "USD"},
            "status": "COMPLETED",
            "location_id": "LOC_1",
            "buyer_email_address": "must-not-persist@example.test",
        });
        let facts = parse_payment(&payment).unwrap();
        assert_eq!(facts.id, "PAY_1");
        assert_eq!(facts.amount, 99);
    }

    #[test]
    fn payment_prefers_tip_inclusive_total_and_normalizes_safe_card_facts() {
        let mut payment = base_payment();
        payment["total_money"] = json!({"amount": 124, "currency": "USD"});
        payment["card_details"] = json!({"card": {"last_4": "4242", "cardholder_name": "Private"}});
        payment["device_details"] = json!({"device_id": "DEVICE_1", "device_name": "Register One"});
        payment["receipt_url"] = json!("https://square.example/receipt");
        let facts = parse_payment(&payment).unwrap();
        assert_eq!(facts.amount, 124);
        assert_eq!(facts.currency, "USD");
        assert_eq!(facts.card_last4, "4242");
        assert_eq!(facts.device_id, "DEVICE_1");
        assert_eq!(facts.device_name, "Register One");
        assert_eq!(facts.receipt_url, "https://square.example/receipt");
    }

    #[test]
    fn offline_payment_uses_client_timestamp_with_server_fallback() {
        let mut payment = base_payment();
        payment["is_offline_payment"] = json!(true);
        payment["offline_payment_details"] =
            json!({"client_created_at": "2026-07-16T15:00:00-07:00"});
        let facts = parse_payment(&payment).unwrap();
        assert_eq!(facts.created_at, "2026-07-16T15:00:00-07:00");
        assert_eq!(
            facts.ts_ms,
            DateTime::parse_from_rfc3339("2026-07-16T15:00:00-07:00")
                .unwrap()
                .timestamp_millis()
        );

        payment["offline_payment_details"] = json!({});
        let fallback = parse_payment(&payment).unwrap();
        assert_eq!(fallback.created_at, "2026-07-16T15:30:00.000Z");
    }

    #[test]
    fn refund_totals_are_normalized_and_currency_fenced() {
        let mut payment = base_payment();
        assert_eq!(parse_payment(&payment).unwrap().refunded_amount, 0);
        payment["refunded_money"] = json!({"amount": 25, "currency": "USD"});
        assert_eq!(parse_payment(&payment).unwrap().refunded_amount, 25);
        for refunded in [
            json!({"amount": -1, "currency": "USD"}),
            json!({"amount": "25", "currency": "USD"}),
            json!({"amount": 25, "currency": "usd"}),
            json!({"amount": 25, "currency": "CAD"}),
            json!({"amount": 25}),
        ] {
            payment["refunded_money"] = refunded;
            assert!(matches!(
                parse_payment(&payment),
                Err(AppError::Unprocessable(_))
            ));
        }
    }

    #[test]
    fn payment_required_and_optional_fields_reject_ambiguous_types() {
        for (path, invalid) in [
            ("id", json!(1)),
            ("created_at", json!(null)),
            ("updated_at", json!([])),
            ("status", json!({})),
            ("location_id", json!(false)),
            ("receipt_url", json!(42)),
        ] {
            let mut payment = base_payment();
            payment[path] = invalid;
            assert!(
                matches!(parse_payment(&payment), Err(AppError::Unprocessable(_))),
                "{path}"
            );
        }
        assert!(matches!(
            parse_payment(&json!([])),
            Err(AppError::Unprocessable(_))
        ));
    }

    #[test]
    fn payment_timestamps_require_explicit_rfc3339_timezone() {
        let mut payment = base_payment();
        payment["created_at"] = json!("2026-07-16T15:30:00");
        assert!(matches!(
            parse_payment(&payment),
            Err(AppError::Unprocessable(_))
        ));
        payment["created_at"] = json!("2026-07-16T15:30:00-07:00");
        assert!(parse_payment(&payment).is_ok());
    }

    #[test]
    fn oauth_authorization_url_is_environment_bound_and_stateful() {
        let url =
            Url::parse(&oauth_authorize_url("sandbox", "sandbox-app-id", "opaque-state").unwrap())
                .unwrap();
        assert_eq!(url.host_str(), Some("connect.squareupsandbox.com"));
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(
            query.get("client_id").map(String::as_str),
            Some("sandbox-app-id")
        );
        assert_eq!(query.get("state").map(String::as_str), Some("opaque-state"));
        assert_eq!(query.get("session").map(String::as_str), Some("false"));
        let scope = query.get("scope").unwrap();
        assert_eq!(scope, "MERCHANT_PROFILE_READ PAYMENTS_READ");
    }

    #[test]
    fn oauth_token_refresh_limits_scopes_to_reads_and_only_targets_authentication() {
        for environment in ["production", "sandbox"] {
            let expected_url = format!("{}/oauth2/token", square_base_url(environment).unwrap());
            for refreshing in [false, true] {
                let request = oauth_token_request(
                    environment,
                    "test-app-id",
                    "test-app-secret",
                    (!refreshing).then_some("test-auth-code"),
                    refreshing.then_some("test-refresh-token"),
                )
                .unwrap()
                .build()
                .unwrap();
                assert_eq!(request.method(), Method::POST);
                assert_eq!(request.url().as_str(), expected_url);
                let body: Value =
                    serde_json::from_slice(request.body().unwrap().as_bytes().unwrap()).unwrap();
                if refreshing {
                    assert_eq!(body["grant_type"], "refresh_token");
                    assert_eq!(
                        body["scopes"],
                        json!(["MERCHANT_PROFILE_READ", "PAYMENTS_READ"])
                    );
                    assert!(body.get("code").is_none());
                } else {
                    assert_eq!(body["grant_type"], "authorization_code");
                    assert!(body.get("refresh_token").is_none());
                }
            }
        }
    }

    #[test]
    fn square_response_shape_helpers_fail_closed() {
        assert!(object_array(&json!({}), "payments").unwrap().is_empty());
        assert!(
            object_array(&json!({"payments": null}), "payments")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            object_array(&json!({"payments": []}), "payments")
                .unwrap()
                .len(),
            0
        );
        assert!(matches!(
            object_array(&json!({"payments": {}}), "payments"),
            Err(AppError::Upstream(_))
        ));
        assert!(
            optional_object(&json!({"value": null}), "value")
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            optional_object(&json!({"value": []}), "value"),
            Err(AppError::Unprocessable(_))
        ));
    }

    #[test]
    fn retry_delay_is_exponential_bounded_and_honors_safe_retry_after() {
        assert_eq!(retry_delay(0, None), Duration::from_millis(500));
        assert_eq!(retry_delay(1, None), Duration::from_secs(1));
        assert_eq!(retry_delay(20, None), Duration::from_secs(10));
        let two = header::HeaderValue::from_static("2");
        let huge = header::HeaderValue::from_static("9999");
        let invalid = header::HeaderValue::from_static("nan");
        assert_eq!(retry_delay(0, Some(&two)), Duration::from_secs(2));
        assert_eq!(retry_delay(0, Some(&huge)), Duration::from_secs(10));
        assert_eq!(retry_delay(0, Some(&invalid)), Duration::from_millis(500));
    }

    #[test]
    fn jpeg_validator_requires_frame_scan_data_and_terminal_eoi() {
        let valid = minimal_jpeg();
        assert!(is_complete_jpeg(&valid));
        assert!(!is_complete_jpeg(b"not-jpeg"));
        assert!(!is_complete_jpeg(&valid[..valid.len() - 2]));
        let mut trailing = valid.clone();
        trailing.extend_from_slice(b"trailing");
        assert!(is_complete_jpeg(&trailing));
        let mut hidden = valid.clone();
        hidden[25] = 0xff;
        hidden[26] = 0xd9;
        assert!(!is_complete_jpeg(&hidden));
    }

    #[test]
    fn webhook_signature_rejects_empty_and_wrong_length_inputs() {
        assert!(!verify_square_webhook_signature(
            "",
            "https://example",
            b"{}",
            "x"
        ));
        assert!(!verify_square_webhook_signature(
            "key",
            "https://example",
            b"{}",
            ""
        ));
        assert!(!verify_square_webhook_signature(
            "key",
            "https://example",
            b"{}",
            "short"
        ));
    }

    #[tokio::test]
    async fn square_locations_send_auth_version_and_normalize_allowlisted_fields() {
        let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = observed.clone();
        let router = Router::new().fallback(any(move |request: Request<Body>| {
            let capture = capture.clone();
            async move {
                capture.lock().unwrap().push((
                    request.uri().to_string(),
                    request
                        .headers()
                        .get(header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("")
                        .to_owned(),
                    request
                        .headers()
                        .get("square-version")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("")
                        .to_owned(),
                ));
                axum::Json(json!({
                    "locations": [{
                        "id": "LOC_1",
                        "name": "Example Location",
                        "status": "ACTIVE",
                        "address": {"private": "not returned"}
                    }]
                }))
            }
        }));
        let client = square_with_router(router).await;
        let locations = client.list_locations().await.unwrap();
        assert_eq!(
            locations,
            [json!({"id": "LOC_1", "name": "Example Location", "status": "ACTIVE"})]
        );
        let observed = observed.lock().unwrap();
        assert_eq!(observed[0].0, "/v2/locations");
        assert_eq!(observed[0].1, "Bearer sandbox-access-token");
        assert_eq!(observed[0].2, SQUARE_VERSION);
    }

    #[tokio::test]
    async fn square_payment_page_preserves_filters_and_rejects_bad_cursor_shape() {
        let uris = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = uris.clone();
        let router = Router::new().fallback(any(move |request: Request<Body>| {
            let capture = capture.clone();
            async move {
                capture.lock().unwrap().push(request.uri().to_string());
                axum::Json(json!({"payments": [{"id": "PAY_1"}], "cursor": "next-page"}))
            }
        }));
        let client = square_with_router(router).await;
        let (payments, cursor) = client
            .payment_page(
                Some("LOC_1"),
                Some("2026-07-16T00:00:00Z"),
                Some("current-page"),
                500,
            )
            .await
            .unwrap();
        assert_eq!(payments, [json!({"id": "PAY_1"})]);
        assert_eq!(cursor.as_deref(), Some("next-page"));
        let uri = uris.lock().unwrap()[0].clone();
        for query in [
            "sort_field=UPDATED_AT",
            "sort_order=ASC",
            "limit=100",
            "location_id=LOC_1",
            "updated_at_begin_time=2026-07-16T00%3A00%3A00Z",
            "cursor=current-page",
        ] {
            assert!(uri.contains(query), "missing {query} in {uri}");
        }

        let router = Router::new().fallback(any(|| async {
            axum::Json(json!({"payments": [], "cursor": []}))
        }));
        let malformed = square_with_router(router).await;
        assert!(matches!(
            malformed.payment_page(None, None, None, 100).await,
            Err(AppError::Upstream(_))
        ));
    }

    #[tokio::test]
    async fn square_data_requests_are_read_only_in_both_environments() {
        for environment in ["production", "sandbox"] {
            let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
            let capture = observed.clone();
            let router = Router::new().fallback(any(move |request: Request<Body>| {
                let capture = capture.clone();
                async move {
                    capture
                        .lock()
                        .unwrap()
                        .push((request.method().clone(), request.uri().path().to_owned()));
                    axum::Json(json!({
                        "locations": [], "merchant": {"id": "EXAMPLE_MERCHANT"}, "payments": []
                    }))
                }
            }));
            let mut client = SquareClient::new("test-read-only-token", environment).unwrap();
            client.base_url = spawn_http(router).await;
            for method in [
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
                Method::HEAD,
                Method::OPTIONS,
                Method::CONNECT,
                Method::TRACE,
            ] {
                for path in [
                    "/v2/payments",
                    "/v2/locations",
                    "/v2/merchants/me",
                    "/v2/refunds",
                    "/v2/webhooks/subscriptions",
                    "/oauth2/revoke",
                ] {
                    assert!(matches!(
                        client.request_json(method.clone(), path, &[]).await,
                        Err(AppError::Forbidden(_))
                    ));
                }
            }
            for path in [
                "/v2/webhooks/subscriptions",
                "/v2/refunds",
                "/oauth2/token",
                "/v2/payments/../refunds",
                "/v2/payments?method=DELETE",
                "/v2/payments/EXAMPLE_PAYMENT/cancel",
                "https://example.invalid/v2/payments",
            ] {
                assert!(matches!(
                    client.request_json(Method::GET, path, &[]).await,
                    Err(AppError::Forbidden(_))
                ));
            }
            assert!(
                observed.lock().unwrap().is_empty(),
                "blocked requests reached the provider"
            );
            client.list_locations().await.unwrap();
            client.merchant_id().await.unwrap();
            client.payment_page(None, None, None, 10).await.unwrap();
            assert_eq!(
                *observed.lock().unwrap(),
                vec![
                    (Method::GET, "/v2/locations".into()),
                    (Method::GET, "/v2/merchants/me".into()),
                    (Method::GET, "/v2/payments".into()),
                ]
            );
        }
    }

    #[tokio::test]
    async fn square_retries_transient_status_and_normalizes_auth_and_json_errors() {
        let calls = Arc::new(AtomicUsize::new(0));
        let sequence = calls.clone();
        let router = Router::new().fallback(any(move || {
            let sequence = sequence.clone();
            async move {
                if sequence.fetch_add(1, Ordering::SeqCst) == 0 {
                    (
                        StatusCode::TOO_MANY_REQUESTS,
                        [(header::RETRY_AFTER, "0")],
                        axum::Json(json!({"errors": []})),
                    )
                        .into_response()
                } else {
                    axum::Json(json!({"locations": []})).into_response()
                }
            }
        }));
        let client = square_with_router(router).await;
        assert!(client.list_locations().await.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        for (status, expected) in [
            (StatusCode::UNAUTHORIZED, "unauthorized"),
            (StatusCode::FORBIDDEN, "forbidden"),
            (StatusCode::SERVICE_UNAVAILABLE, "upstream"),
        ] {
            let router = Router::new().fallback(any(move || async move {
                (status, axum::Json(json!({"error": true}))).into_response()
            }));
            let client = square_with_router(router).await;
            let error = client.list_locations().await.unwrap_err();
            assert!(
                matches!(
                    (&error, expected),
                    (AppError::Unauthorized(_), "unauthorized")
                        | (AppError::Forbidden(_), "forbidden")
                        | (AppError::Upstream(_), "upstream")
                ),
                "{error:?}"
            );
        }
        let router = Router::new().fallback(any(|| async {
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/html")],
                "<html>not json</html>",
            )
        }));
        let client = square_with_router(router).await;
        assert!(matches!(
            client.list_locations().await,
            Err(AppError::Upstream(_))
        ));
    }

    #[tokio::test]
    async fn square_read_requests_do_not_follow_redirects_outside_the_allowlist() {
        let redirected = Arc::new(AtomicUsize::new(0));
        let capture = redirected.clone();
        let target = spawn_http(Router::new().fallback(any(move || {
            let capture = capture.clone();
            async move {
                capture.fetch_add(1, Ordering::SeqCst);
                axum::Json(json!({"locations": []}))
            }
        })))
        .await;
        for code in [301, 302, 303, 307, 308] {
            let target = format!("{target}/v2/webhooks/subscriptions");
            let router = Router::new().fallback(any(move || {
                let target = target.clone();
                async move {
                    (
                        StatusCode::from_u16(code).unwrap(),
                        [(header::LOCATION, target)],
                    )
                }
            }));
            let client = square_with_router(router).await;
            assert!(matches!(
                client.list_locations().await,
                Err(AppError::Upstream(_))
            ));
        }
        assert_eq!(redirected.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn protect_session_login_camera_normalization_and_relogin_are_native() {
        let logins = Arc::new(AtomicUsize::new(0));
        let bootstraps = Arc::new(AtomicUsize::new(0));
        let csrf = Arc::new(std::sync::Mutex::new(Vec::new()));
        let login_count = logins.clone();
        let bootstrap_count = bootstraps.clone();
        let observed_csrf = csrf.clone();
        let router = Router::new().fallback(any(move |request: Request<Body>| {
            let login_count = login_count.clone();
            let bootstrap_count = bootstrap_count.clone();
            let observed_csrf = observed_csrf.clone();
            async move {
                match request.uri().path() {
                    "/api/auth/login" => {
                        login_count.fetch_add(1, Ordering::SeqCst);
                        (
                            StatusCode::OK,
                            [
                                ("x-csrf-token", "csrf-token"),
                                ("set-cookie", "TOKEN=session; Path=/"),
                            ],
                            axum::Json(json!({"ok": true})),
                        )
                            .into_response()
                    }
                    "/proxy/protect/api/bootstrap" => {
                        observed_csrf.lock().unwrap().push(
                            request
                                .headers()
                                .get("x-csrf-token")
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or("")
                                .to_owned(),
                        );
                        if bootstrap_count.fetch_add(1, Ordering::SeqCst) == 0 {
                            StatusCode::UNAUTHORIZED.into_response()
                        } else {
                            axum::Json(json!({
                                "nvr": {"id": "CONSOLE_1"},
                                "cameras": [
                                    {"id": "abc123", "name": "Checkout Camera", "state": "CONNECTED"},
                                    {"id": "def456", "name": "", "marketName": "G5 Dome"}
                                ]
                            }))
                            .into_response()
                        }
                    }
                    _ => StatusCode::NOT_FOUND.into_response(),
                }
            }
        }));
        let client = protect_with_router(router, None).await;
        let (cameras, console) = client.cameras_with_console_identity().await.unwrap();
        assert_eq!(logins.load(Ordering::SeqCst), 2);
        assert_eq!(bootstraps.load(Ordering::SeqCst), 2);
        assert_eq!(console.as_deref(), Some("CONSOLE_1"));
        assert_eq!(cameras[0]["name"], "Checkout Camera");
        assert_eq!(cameras[1]["name"], "G5 Dome");
        assert!(
            csrf.lock()
                .unwrap()
                .iter()
                .all(|value| value == "csrf-token")
        );
    }

    #[tokio::test]
    async fn protect_historical_snapshot_uses_recording_endpoint_and_validates_jpeg() {
        let paths = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = paths.clone();
        let jpeg = minimal_jpeg();
        let router = Router::new().fallback(any(move |request: Request<Body>| {
            let capture = capture.clone();
            let jpeg = jpeg.clone();
            async move {
                let path = request.uri().to_string();
                capture.lock().unwrap().push(path.clone());
                if path == "/api/auth/login" {
                    return (StatusCode::OK, [("x-csrf-token", "csrf")], Vec::new())
                        .into_response();
                }
                if path.contains("recording-snapshot?ts=1234") {
                    return (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "image/jpeg; charset=binary")],
                        jpeg,
                    )
                        .into_response();
                }
                StatusCode::NOT_FOUND.into_response()
            }
        }));
        let client = protect_with_router(router, None).await;
        assert_eq!(
            client.snapshot("abc123", Some(1234)).await.unwrap(),
            minimal_jpeg()
        );
        assert!(
            paths
                .lock()
                .unwrap()
                .iter()
                .any(|path| path.contains("/cameras/abc123/recording-snapshot?ts=1234"))
        );

        let router = Router::new().fallback(any(|request: Request<Body>| async move {
            if request.uri().path() == "/api/auth/login" {
                (StatusCode::OK, [("x-csrf-token", "csrf")], Vec::new()).into_response()
            } else {
                StatusCode::NOT_FOUND.into_response()
            }
        }));
        let missing = protect_with_router(router, None).await;
        assert!(matches!(
            missing.snapshot("abc123", Some(1234)).await,
            Err(AppError::Upstream(message)) if message.contains("No recording available")
        ));
    }

    #[tokio::test]
    async fn protect_integration_api_uses_only_api_key_and_encodes_alarm_id() {
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = requests.clone();
        let router = Router::new().fallback(any(move |request: Request<Body>| {
            let capture = capture.clone();
            async move {
                capture.lock().unwrap().push((
                    request.uri().to_string(),
                    request
                        .headers()
                        .get("x-api-key")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("")
                        .to_owned(),
                    request.headers().get(header::COOKIE).is_some(),
                ));
                if request.uri().path().ends_with("/meta/info") {
                    axum::Json(json!({"applicationVersion": "7.1.87"})).into_response()
                } else {
                    StatusCode::NO_CONTENT.into_response()
                }
            }
        }));
        let client = protect_with_router(router, Some("integration-key")).await;
        assert_eq!(
            client.integration_info().await.unwrap()["applicationVersion"],
            "7.1.87"
        );
        client
            .trigger_alarm(" Checkout Camera/Sale ")
            .await
            .unwrap();
        client.trigger_alarm("Checkout+Camera").await.unwrap();
        let requests = requests.lock().unwrap();
        assert!(
            requests
                .iter()
                .all(|request| request.1 == "integration-key")
        );
        assert!(requests.iter().all(|request| !request.2));
        assert!(
            requests[1].0.ends_with("/Checkout%20Camera%2FSale"),
            "unexpected alarm path: {:?}",
            requests[1].0
        );
        assert!(
            requests[2].0.ends_with("/Checkout%2BCamera"),
            "unexpected literal-plus path: {:?}",
            requests[2].0
        );
    }

    #[test]
    fn rejects_ambiguous_square_payment_field_types() {
        let base = json!({
            "id": "PAY_1",
            "created_at": "2026-07-16T15:30:00.000Z",
            "amount_money": {"amount": 99, "currency": "USD"},
            "status": "COMPLETED",
        });
        for invalid in [
            {
                let mut value = base.clone();
                value["amount_money"]["amount"] = json!("99");
                value
            },
            {
                let mut value = base.clone();
                value["device_details"] = json!({"device_id": 42});
                value
            },
            {
                let mut value = base.clone();
                value["is_offline_payment"] = json!(true);
                value["offline_payment_details"] = json!({"client_created_at": 42});
                value
            },
            {
                let mut value = base.clone();
                value["refunded_money"] = json!({"amount": 1, "currency": "usd"});
                value
            },
        ] {
            assert!(matches!(
                parse_payment(&invalid),
                Err(AppError::Unprocessable(_))
            ));
        }
    }
}
