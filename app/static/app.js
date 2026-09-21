/* Square × UniFi Protect frontend. All dynamic text is set via textContent —
   server data is never interpreted as markup, which rules out DOM XSS. */
"use strict";

const $ = (sel) => document.querySelector(sel);
const TRANSACTION_REFRESH_MS = 15000;
const TRANSACTION_PAGE_SIZE = 100;

let transactionRefreshTimer = null;
let transactionLoadInFlight = false;
let transactionPendingOffset = null;
let transactionOffset = 0;
let transactionHasNext = false;
let transactionPageCount = 0;
let transactionSnapshot = null;
let transactionFilters = normalizeTransactionFilters("", "");
let lastTransactionPayload = null;
let settingsLoadGeneration = 0;
let squareAccountSwitchConfirmationToken = "";
let squareAccountRevision = "";
let cameraMappingGeneration = "";
let wizardSquareAccountRevision = "";
let wizardProtectConsoleGeneration = "";
let currentUser = null;
let motionSettingsCameras = [];
let motionAlertLoadGeneration = 0;
let squareOAuthSettings = null;
let squareOAuthLoadGeneration = 0;
let squareOAuthDirty = false;
let squareOAuthBusy = false;
let squareOAuthReturnFeedback = null;

function setCurrentUser(payload) {
  currentUser = sessionUser(payload);
  applyRoleInterface(
    currentUser,
    document.querySelectorAll("[data-admin-only]"),
    $("#session-identity"),
  );
  return currentUser;
}

function leaveAppForLogin(username = "admin") {
  stopTransactionRefresh();
  setCurrentUser(null);
  $("#nav").hidden = true;
  $("#login-username").value = username;
  show("#view-login");
}

function show(viewId, focusHeading = true) {
  const view = $(viewId);
  activateViewState(
    document.querySelectorAll("main > section"),
    view,
    document.querySelectorAll("nav button[data-view]"),
  );
  if (focusHeading) focusViewHeading(view);
  window.dispatchEvent(new Event("squareprotect:ready"));
}

function message(text, kind) {
  const el = $("#message");
  el.textContent = text || "";
  el.className = kind || "";
}

async function api(path, options = {}) {
  const { includeResponse = false, headers = {}, ...requestOptions } = options;
  const resp = await fetch(path, {
    credentials: "same-origin",
    ...requestOptions,
    headers: { "Content-Type": "application/json", ...headers },
  });
  const data = await resp.json().catch(() => ({}));
  // Only an expired/missing app session should bounce to the login view.
  // Settings endpoints also return 401 when UniFi Protect or Square reject
  // the submitted credentials; those must surface as inline errors instead
  // of asking the operator to log out and back in.
  const sessionExpired =
    resp.status === 401 &&
    path !== "/api/login" &&
    data.detail === "Authentication required";
  if (sessionExpired) {
    leaveAppForLogin(currentUser ? currentUser.username : "admin");
    throw sessionExpiredError();
  }
  if (!resp.ok) {
    const detail = data.detail;
    const error = new Error(
      detail && typeof detail === "object" && detail.message
        ? detail.message
        : detail || `Request failed (${resp.status})`,
    );
    error.status = resp.status;
    if (detail && typeof detail === "object") {
      error.code = detail.code;
      error.confirmationToken = detail.confirmation_token;
    }
    throw error;
  }
  return includeResponse ? { data, response: resp } : data;
}

// ---------------------------------------------------------------- boot

function showBootFailure(error) {
  $("#nav").hidden = true;
  $("#boot-error-detail").textContent = bootFailureMessage(error);
  $("#boot-retry").disabled = false;
  show("#view-boot-error");
}

async function boot() {
  const oauthOutcome = new URLSearchParams(window.location.search).get("square_oauth");
  const oauthFeedback = squareOAuthResultFeedback(window.location.search);
  squareOAuthReturnFeedback = oauthFeedback;
  if (oauthFeedback) {
    message(oauthFeedback.text, oauthFeedback.kind);
    window.history.replaceState({}, "", "/");
  }
  let status;
  try {
    status = await api("/api/status");
  } catch (err) {
    showBootFailure(err);
    return;
  }
  if (!status.setup_complete) {
    show("#view-setup");
    return;
  }
  // Resolve the live account role before choosing any application view.
  try {
    const session = await api("/api/session");
    if (!setCurrentUser(session)) throw new Error("Invalid session response");
    await enterAppOrWizard();
    if (isAdmin(currentUser) && oauthOutcome && oauthFeedback) {
      show("#view-settings");
      $("#square-connection-summary").focus();
    }
  } catch (err) {
    if (isSessionExpiredError(err)) return;
    showBootFailure(err);
  }
}

$("#boot-retry").addEventListener("click", () => {
  $("#boot-retry").disabled = true;
  $("#boot-error-detail").textContent = "Retrying…";
  void boot();
});

function enterApp() {
  $("#nav").hidden = false;
  show("#view-transactions");
  loadTransactions({ reset: true });
  void loadMotionAlerts();
  if (isAdmin(currentUser)) {
    loadSettingsView();
    void loadUsers();
    void loadLoginAudit({ reset: true });
  }
  startTransactionRefresh();
  startDashboardRefresh();
}

async function enterAppOrWizard() {
  if (isAdmin(currentUser) && await maybeStartWizard()) {
    startTransactionRefresh();
    void loadTransactions({ reset: true });
    return;
  }
  enterApp();
}

// ---------------------------------------------------------------- auth

$("#setup-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const bootstrapSecret = $("#setup-bootstrap-secret").value;
  const transportError = bootstrapTransportError(window.location);
  if (transportError) {
    message(transportError, "error");
    return;
  }
  try {
    await api("/api/setup", {
      method: "POST",
      body: JSON.stringify({
        password: $("#setup-password").value,
        bootstrap_secret: bootstrapSecret,
      }),
    });
    $("#setup-password").value = "";
    $("#setup-bootstrap-secret").value = "";
    $("#login-username").value = "admin";
    message("Administrator account created. Log in as admin.", "ok");
    show("#view-login");
  } catch (err) {
    message(err.message, "error");
  }
});

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const result = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({
        username: $("#login-username").value.trim(),
        password: $("#login-password").value,
      }),
    });
    if (!setCurrentUser(result)) throw new Error("Invalid session response");
    $("#login-password").value = "";
    message("", "");
    await enterAppOrWizard();
  } catch (err) {
    message(err.message, "error");
  }
});

$("#logout-btn").addEventListener("click", async () => {
  const username = currentUser ? currentUser.username : "admin";
  try { await api("/api/logout", { method: "POST" }); } catch { /* session gone */ }
  leaveAppForLogin(username);
});

for (const btn of document.querySelectorAll("nav button[data-view]")) {
  btn.addEventListener("click", () => {
    if (btn.dataset.view === "settings" && !isAdmin(currentUser)) return;
    show(`#view-${btn.dataset.view}`);
    if (btn.dataset.view === "transactions") {
      loadTransactions();
      void loadMotionAlerts();
    }
    if (btn.dataset.view === "settings") {
      loadSettingsView();
      void loadUsers();
      void loadLoginAudit({ reset: true });
    }
  });
}

// ---------------------------------------------------------------- settings

let userLoadGeneration = 0;
let loginAuditGeneration = 0;
let loginAuditCursor = null;
let loginAuditEvents = [];

function renderLoginAudit() {
  const container = $("#login-audit-list");
  container.textContent = "";
  if (!loginAuditEvents.length) {
    container.textContent = "No successful logins recorded yet.";
    return;
  }
  for (const event of loginAuditEvents) {
    const row = document.createElement("div");
    row.className = "login-audit-row";
    const identity = document.createElement("div");
    const username = document.createElement("strong");
    username.textContent = event.username;
    const role = document.createElement("span");
    role.className = "hint";
    role.textContent = ` · ${accountRoleLabel(event.role)}`;
    identity.append(username, role);
    const detail = document.createElement("p");
    detail.className = "hint";
    const when = new Date(event.loggedInAt * 1000).toLocaleString();
    detail.textContent = `${when} · ${event.clientIp}`;
    row.append(identity, detail);
    container.appendChild(row);
  }
}

async function loadLoginAudit({ reset = false } = {}) {
  if (!isAdmin(currentUser)) return;
  const generation = ++loginAuditGeneration;
  const beforeId = reset ? null : loginAuditCursor;
  if (!reset && beforeId === null) return;
  const button = $("#login-audit-more");
  button.disabled = true;
  try {
    const cursor = beforeId === null ? "" : `&before_id=${beforeId}`;
    const payload = await api(`/api/login-audit?limit=100${cursor}`);
    if (generation !== loginAuditGeneration) return;
    const page = loginAuditPage(payload);
    loginAuditEvents = reset
      ? page.events
      : [...loginAuditEvents, ...page.events];
    loginAuditCursor = page.nextBeforeId;
    renderLoginAudit();
    button.hidden = loginAuditCursor === null;
  } catch (error) {
    if (generation === loginAuditGeneration) message(error.message, "error");
  } finally {
    if (generation === loginAuditGeneration) button.disabled = false;
  }
}

$("#login-audit-more").addEventListener("click", () => {
  void loadLoginAudit();
});

function renderUsers(payload) {
  const container = $("#user-list");
  container.textContent = "";
  const accounts = userAccounts(payload);
  if (!accounts.length) {
    container.textContent = "No user accounts found.";
    return;
  }
  for (const account of accounts) {
    const row = document.createElement("article");
    row.className = "user-row";
    const heading = document.createElement("div");
    heading.className = "user-heading";
    const username = document.createElement("strong");
    username.textContent = account.username;
    const detail = document.createElement("span");
    detail.className = "hint";
    const current = account.current ? " · current account" : "";
    const disabled = account.enabled ? "" : " · disabled";
    const created = new Date(account.createdAt * 1000).toLocaleString();
    detail.textContent = `${accountRoleLabel(account.role)}${current}${disabled} · added ${created}`;
    heading.append(username, detail);

    const form = document.createElement("form");
    form.className = "user-reset-form";
    const passwordLabel = document.createElement("label");
    passwordLabel.textContent = "New password";
    const password = document.createElement("input");
    password.type = "password";
    password.minLength = 8;
    password.maxLength = 256;
    password.autocomplete = "new-password";
    password.required = true;
    passwordLabel.appendChild(password);
    const confirmLabel = document.createElement("label");
    confirmLabel.textContent = "Confirm password";
    const confirmation = document.createElement("input");
    confirmation.type = "password";
    confirmation.minLength = 8;
    confirmation.maxLength = 256;
    confirmation.autocomplete = "new-password";
    confirmation.required = true;
    confirmLabel.appendChild(confirmation);
    const submit = document.createElement("button");
    submit.type = "submit";
    submit.textContent = "Reset password";
    form.append(passwordLabel, confirmLabel, submit);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const validationError = passwordPairError(
        password.value,
        confirmation.value,
      );
      if (validationError) {
        message(validationError, "error");
        return;
      }
      submit.disabled = true;
      try {
        const result = await api(`/api/users/${account.id}/password`, {
          method: "PUT",
          body: JSON.stringify({ password: password.value }),
        });
        password.value = "";
        confirmation.value = "";
        if (result.current_session_revoked) {
          leaveAppForLogin(account.username);
          message("Your password was reset. Log in with the new password.", "ok");
          return;
        }
        message(`Password reset for ${account.username}; existing sessions were signed out.`, "ok");
        void loadUsers();
      } catch (error) {
        message(error.message, "error");
      } finally {
        submit.disabled = false;
      }
    });

    row.append(heading, form);
    container.appendChild(row);
  }
}

async function loadUsers() {
  if (!isAdmin(currentUser)) return;
  const generation = ++userLoadGeneration;
  try {
    const payload = await api("/api/users");
    if (generation === userLoadGeneration) renderUsers(payload);
  } catch (error) {
    if (generation === userLoadGeneration) message(error.message, "error");
  }
}

$("#user-create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const submit = $("#user-create-form button[type='submit']");
  const password = $("#user-create-password").value;
  const confirmation = $("#user-create-password-confirm").value;
  const validationError = passwordPairError(password, confirmation);
  if (validationError) {
    message(validationError, "error");
    return;
  }
  submit.disabled = true;
  try {
    const result = await api("/api/users", {
      method: "POST",
      body: JSON.stringify({
        username: $("#user-create-username").value.trim(),
        password,
        role: $("#user-create-role").value,
      }),
    });
    $("#user-create-username").value = "";
    $("#user-create-password").value = "";
    $("#user-create-password-confirm").value = "";
    message(`User ${result.user.username} added.`, "ok");
    void loadUsers();
  } catch (error) {
    message(error.message, "error");
  } finally {
    submit.disabled = false;
  }
});

const loadDeepLinkSettings = createLatestDeepLinkSettingsLoader(
  () => api("/api/settings/deep-link"),
  (settings) => applyDeepLinkSettings(
    $("#deep-link-template"),
    $("#deep-link-status"),
    settings,
  ),
);

function formatStorageBytes(bytes) {
  const value = Math.max(0, Number(bytes) || 0);
  if (value < 1024) return `${value} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let amount = value;
  let unit = "B";
  for (const candidate of units) {
    amount /= 1024;
    unit = candidate;
    if (amount < 1024) break;
  }
  return `${amount.toFixed(amount >= 10 ? 1 : 2)} ${unit}`;
}

function renderThumbnailStorageSettings(settings) {
  $("#thumbnail-compression-enabled").checked = settings.compression_enabled;
  $("#thumbnail-jpeg-quality").value = settings.jpeg_quality;
  $("#thumbnail-max-dimension").value = settings.max_dimension;
  $("#thumbnail-retention-days").value = settings.retention_days;
  $("#thumbnail-max-storage-mib").value = settings.max_storage_mib;
  const usage = settings.usage || {};
  const maintenance = settings.maintenance || {};
  const parts = [
    `${usage.active_count || 0} thumbnail(s) using ${formatStorageBytes(usage.active_bytes)}`,
    `${usage.retired_count || 0} expired`,
  ];
  if (["queued", "running"].includes(maintenance.state)) {
    parts.push("maintenance running…");
  } else if (maintenance.state === "error") {
    parts.push(maintenance.error || "maintenance failed");
  } else if (maintenance.result) {
    parts.push(`${formatStorageBytes(maintenance.result.bytes_saved)} reclaimed last run`);
  }
  $("#thumbnail-storage-status").textContent = parts.join(" · ");
}

const loadThumbnailStorageSettings = createLatestSettingsLoader(
  () => api("/api/settings/thumbnail-storage"),
  renderThumbnailStorageSettings,
);

async function pollThumbnailMaintenance() {
  try {
    const settings = await api("/api/settings/thumbnail-storage");
    renderThumbnailStorageSettings(settings);
    if (["queued", "running"].includes(settings.maintenance?.state)) {
      window.setTimeout(pollThumbnailMaintenance, 750);
    } else {
      $("#thumbnail-optimize-existing").disabled = false;
    }
  } catch (err) {
    $("#thumbnail-optimize-existing").disabled = false;
    message(err.message, "error");
  }
}

$("#protect-discover").addEventListener("click", async () => {
  const button = $("#protect-discover");
  if (button.disabled) return;
  button.disabled = true;
  const results = $("#protect-discover-results");
  results.textContent = "Scanning the local network (a few seconds)…";
  const typedHost = $("#protect-host").value.trim();
  try {
    const devices = await api("/api/discover/protect", {
      method: "POST",
      body: JSON.stringify({ host: typedHost }),
    });
    results.textContent = "";
    const consoles = devices.filter((d) => d.is_console);
    if (!consoles.length) {
      results.textContent = typedHost
        ? "No console answered. Check the IP, or your console may be on another network segment."
        : "No console found on this network. If yours is on another network segment, type its IP above and press this button to verify it.";
      return;
    }
    for (const device of consoles) {
      const row = document.createElement("div");
      const pick = document.createElement("button");
      pick.type = "button";
      pick.textContent = `Use ${device.name} (${device.model} at ${device.ip})`;
      pick.addEventListener("click", () => {
        $("#protect-host").value = device.ip;
        results.textContent = `Selected ${device.name} — confirm this really is your console before entering credentials, then sign in below and press Connect Protect.`;
      });
      row.appendChild(pick);
      results.appendChild(row);
    }
  } catch (err) {
    results.textContent = err.message;
  } finally {
    button.disabled = false;
  }
});

$("#protect-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const confirmationCheckbox = $("#protect-confirm-console-switch");
  try {
    const settings = {
      host: $("#protect-host").value.trim(),
      username: $("#protect-username").value.trim(),
      password: $("#protect-password").value,
      verify_ssl: $("#protect-verify-ssl").checked,
      api_key: $("#protect-api-key").value.trim(),
      alarm_trigger_id: $("#protect-alarm-trigger-id").value.trim(),
    };
    const tokenRequest = protectConsoleSwitchTokenRequest(
      confirmationCheckbox,
      settings,
    );
    let consoleSwitchToken = "";
    if (tokenRequest) {
      const confirmation = await api(
        "/api/settings/protect/console-switch-token",
        {
          method: "POST",
          body: JSON.stringify(tokenRequest),
        },
      );
      consoleSwitchToken = confirmation.token;
    }
    const result = await api("/api/settings/protect", {
      method: "PUT",
      body: JSON.stringify({
        ...settings,
        console_switch_token: consoleSwitchToken,
      }),
    });
    $("#protect-password").value = "";
    $("#protect-api-key").value = "";
    confirmationCheckbox.checked = false;
    let settingsReload = null;
    if (result.console_switched) {
      settingsLoadGeneration += 1;
      squareAccountRevision = "";
      cameraMappingGeneration = "";
      clearProtectConsoleView(
        $("#mapping-rows"),
        $("#save-mapping"),
        $("#camera-preview-wrap"),
        $("#camera-preview"),
      );
      clearProtectAlarmSettingsView();
      clearProtectMotionSettingsView();
      lastTransactionPayload = null;
      renderTransactions([]);
      settingsReload = loadSettingsView();
      await Promise.all([
        loadTransactions({ reset: true }),
        settingsReload,
      ]);
    }
    message(protectConnectionMessage(result), "ok");
    if (!settingsReload) loadSettingsView();
  } catch (err) {
    // Any failed or conflicted save requires a fresh user confirmation and a
    // newly issued token bound to the then-current console generation.
    confirmationCheckbox.checked = false;
    message(err.message, "error");
  }
});

$("#protect-disable-alarm").addEventListener("click", async () => {
  try {
    await api("/api/settings/protect/alarm", { method: "DELETE" });
    $("#protect-api-key").value = "";
    $("#protect-alarm-trigger-id").value = "";
    clearProtectAlarmSettingsView();
    message("Protect alarm trigger disabled.", "ok");
    void loadSettingsView();
  } catch (err) {
    message(err.message, "error");
  }
});

function clearProtectAlarmSettingsView() {
  $("#protect-alarm-status").textContent = "Transaction flags not enabled.";
  $("#protect-test-alarm").hidden = true;
}

function renderProtectAlarmSettings(payload) {
  const status = protectAlarmStatus(payload);
  const button = $("#protect-test-alarm");
  button.hidden = !status.configured;
  if (!status.configured) {
    clearProtectAlarmSettingsView();
    return;
  }
  const active = status.pending + status.inProgress;
  const last = status.lastDeliveredAtMs === null
    ? "no transaction flags accepted yet"
    : `last accepted ${new Date(status.lastDeliveredAtMs).toLocaleString()}`;
  $("#protect-alarm-status").textContent =
    `Enabled for trigger “${status.triggerId}” · ${status.delivered} accepted · ${active} pending · ${last}`;
}

$("#protect-test-alarm").addEventListener("click", async () => {
  const confirmed = window.confirm(
    "This runs the configured Protect Alarm Manager actions now. Send one test flag?",
  );
  if (!confirmed) return;
  const button = $("#protect-test-alarm");
  button.disabled = true;
  try {
    const result = await api("/api/settings/protect/alarm/test", {
      method: "POST",
    });
    renderProtectAlarmSettings(result);
    const accepted = protectAlarmStatus(result).testAcceptedAtMs;
    message(
      accepted === null
        ? "Protect accepted the test transaction flag."
        : `Protect accepted the test transaction flag at ${new Date(accepted).toLocaleString()}.`,
      "ok",
    );
  } catch (error) {
    message(error.message, "error");
  } finally {
    button.disabled = false;
  }
});

$("#deep-link-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const result = await api("/api/settings/deep-link", {
      method: "PUT",
      body: JSON.stringify(deepLinkSettingsRequest($("#deep-link-template"))),
    });
    loadDeepLinkSettings.invalidate();
    applyDeepLinkSettings(
      $("#deep-link-template"),
      $("#deep-link-status"),
      result,
    );
    message(
      result.template
        ? "Custom Protect timeline link saved."
        : "Protect timeline link restored to the built-in default.",
      "ok",
    );
  } catch (err) {
    message(err.message, "error");
  }
});

function clearProtectMotionSettingsView() {
  motionSettingsCameras = [];
  const select = $("#protect-motion-camera");
  select.textContent = "";
  const none = document.createElement("option");
  none.value = "";
  none.textContent = "— choose camera —";
  select.appendChild(none);
  $("#protect-motion-setup").hidden = true;
  $("#protect-motion-url").textContent = "";
  $("#protect-motion-header").textContent = "";
  $("#protect-motion-token").textContent = "";
  $("#protect-motion-token-hint").textContent = "";
  const lastEvent = $("#protect-motion-last-event");
  lastEvent.removeAttribute("datetime");
  lastEvent.textContent = "Checking for motion webhook activity…";
  lastEvent.parentElement.dataset.received = "false";
}

function renderProtectMotionLastEvent(lastEventMs) {
  const status = protectMotionReceiptStatus(lastEventMs);
  const lastEvent = $("#protect-motion-last-event");
  lastEvent.parentElement.dataset.received = String(status.received);
  if (!status.received) {
    lastEvent.removeAttribute("datetime");
    lastEvent.textContent = status.relativeText;
    return;
  }
  lastEvent.setAttribute("datetime", status.dateTime);
  lastEvent.textContent =
    `${new Date(status.timestampMs).toLocaleString()} · ${status.relativeText}`;
}

function renderProtectMotionSettings(payload, cameras) {
  const settings = protectMotionSettings(payload);
  const select = $("#protect-motion-camera");
  select.textContent = "";
  const none = document.createElement("option");
  none.value = "";
  none.textContent = "— choose camera —";
  select.appendChild(none);
  for (const camera of cameras || []) {
    const option = document.createElement("option");
    option.value = camera.id;
    option.textContent = camera.name;
    option.selected = camera.id === settings.cameraId;
    select.appendChild(option);
  }
  if (
    settings.cameraId &&
    !(cameras || []).some((camera) => camera.id === settings.cameraId)
  ) {
    const unavailable = document.createElement("option");
    unavailable.value = settings.cameraId;
    unavailable.textContent = `${settings.cameraName || settings.cameraId} — unavailable`;
    unavailable.selected = true;
    unavailable.disabled = true;
    select.appendChild(unavailable);
  }
  $("#protect-motion-match-window").value = settings.matchWindowSeconds;
  $("#protect-motion-grace").value = settings.graceSeconds;
  $("#protect-motion-retention").value = settings.retentionDays;
  $("#protect-motion-rotate-token").checked = false;
  renderProtectMotionLastEvent(settings.lastEventMs);

  const setup = $("#protect-motion-setup");
  setup.hidden = !settings.enabled;
  if (!settings.enabled) return;
  $("#protect-motion-url").textContent = protectMotionWebhookUrl(
    window.location.origin,
    settings.webhookPath,
  );
  $("#protect-motion-header").textContent = settings.webhookHeader;
  $("#protect-motion-token").textContent = settings.webhookToken || "Not displayed";
  $("#protect-motion-token-hint").textContent = settings.webhookToken
    ? "Copy this value now. It is shown only when created or rotated."
    : "The token is stored securely. Select Rotate the webhook token and save to reveal a replacement.";
}

const refreshProtectMotionLastEvent = createLatestStatusRefresher(
  async () => {
    try {
      return {
        loaded: true,
        payload: await api("/api/settings/protect/motion-webhook"),
      };
    } catch {
      return { loaded: false, payload: null };
    }
  },
  (result) => {
    if (result.loaded) {
      renderProtectMotionLastEvent(
        protectMotionSettings(result.payload).lastEventMs,
      );
    }
  },
);

$("#protect-motion-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const submit = $("#protect-motion-form button[type='submit']");
  submit.disabled = true;
  try {
    const result = await api("/api/settings/protect/motion-webhook", {
      method: "PUT",
      body: JSON.stringify(protectMotionSettingsRequest({
        cameraId: $("#protect-motion-camera").value,
        matchWindowSeconds: $("#protect-motion-match-window").value,
        graceSeconds: $("#protect-motion-grace").value,
        retentionDays: $("#protect-motion-retention").value,
        rotateToken: $("#protect-motion-rotate-token").checked,
      })),
    });
    renderProtectMotionSettings(result, motionSettingsCameras);
    message("Protect motion webhook saved. Configure or test its Alarm Manager action.", "ok");
    void loadMotionAlerts();
  } catch (error) {
    message(error.message, "error");
  } finally {
    submit.disabled = false;
  }
});

$("#protect-motion-disable").addEventListener("click", async () => {
  try {
    const result = await api("/api/settings/protect/motion-webhook", {
      method: "DELETE",
    });
    renderProtectMotionSettings(result, motionSettingsCameras);
    message("Protect motion webhook disabled; its token is no longer valid.", "ok");
    void loadMotionAlerts();
  } catch (error) {
    message(error.message, "error");
  }
});

$("#thumbnail-storage-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const settings = await api("/api/settings/thumbnail-storage", {
      method: "PUT",
      body: JSON.stringify({
        compression_enabled: $("#thumbnail-compression-enabled").checked,
        jpeg_quality: Number($("#thumbnail-jpeg-quality").value),
        max_dimension: Number($("#thumbnail-max-dimension").value),
        retention_days: Number($("#thumbnail-retention-days").value),
        max_storage_mib: Number($("#thumbnail-max-storage-mib").value),
      }),
    });
    renderThumbnailStorageSettings(settings);
    void pollThumbnailMaintenance();
    message("Thumbnail storage controls saved.", "ok");
  } catch (err) {
    message(err.message, "error");
  }
});

$("#thumbnail-optimize-existing").addEventListener("click", async () => {
  const button = $("#thumbnail-optimize-existing");
  button.disabled = true;
  try {
    const settings = await api(
      "/api/settings/thumbnail-storage/maintenance",
      { method: "POST" },
    );
    renderThumbnailStorageSettings(settings);
    void pollThumbnailMaintenance();
    message("Existing-thumbnail optimization started.", "ok");
  } catch (err) {
    button.disabled = false;
    message(err.message, "error");
  }
});

function squareOAuthMessage(text, kind = "") {
  const el = $("#square-oauth-save-result");
  el.textContent = text;
  el.className = `square-oauth-feedback ${kind}`;
}

function squareOAuthSignInMessage(text, kind = "") {
  const el = $("#square-oauth-signin-result");
  el.textContent = text;
  el.className = `square-oauth-feedback ${kind}`;
}

function updateSquareOAuthControls() {
  if (!squareOAuthSettings) return;
  const view = squareOAuthView(squareOAuthSettings, squareOAuthDirty);
  $("#square-oauth-next-step").textContent = view.nextStep;
  const connect = $("#square-oauth-connect");
  connect.textContent = view.connectLabel;
  connect.disabled = squareOAuthBusy || !view.canConnect;
  $("#square-oauth-save").disabled = squareOAuthBusy;
  $("#square-oauth-save").textContent = squareOAuthBusy ? "Saving…" : "Save credentials";
  const keepSecret = squareOAuthCanKeepSecret(
    squareOAuthSettings, $("#square-oauth-client-id").value, $("#square-oauth-env").value,
  );
  $("#square-oauth-secret").required = !keepSecret;
  $("#square-oauth-secret").placeholder = keepSecret ? "Saved — leave blank to keep" : "Enter application secret";
  $("#square-oauth-secret-hint").textContent = keepSecret
    ? "A secret is already saved for this application. Leave blank to keep it, or enter a replacement."
    : "Enter the secret for this application and environment from Square.";
  for (const id of ["#square-oauth-client-id", "#square-oauth-secret", "#square-oauth-env"]) {
    $(id).disabled = squareOAuthBusy;
  }
}

function renderSquareOAuthSettings(settings) {
  if (!squareOAuthSettings) squareOAuthMessage("");
  squareOAuthSettings = settings;
  const view = squareOAuthView(settings, squareOAuthDirty);
  $("#square-active-connection").textContent = view.activeTitle;
  $("#square-active-detail").textContent = view.activeDetail;
  $("#square-oauth-saved-status").textContent = view.savedStatus;
  $("#square-oauth-redirect-url").textContent = `${window.location.origin}/oauth/square/callback`;
  $("#square-oauth-switch-warning").hidden = !settings.pending_environment;
  if (!squareOAuthDirty) {
    $("#square-oauth-client-id").value = settings.client_id;
    $("#square-oauth-env").value = settings.environment;
  }
  updateSquareOAuthControls();
  if (squareOAuthReturnFeedback) {
    squareOAuthSignInMessage(squareOAuthReturnFeedback.text, squareOAuthReturnFeedback.kind);
  }
}

async function loadSquareOAuthSettings() {
  if (squareOAuthBusy) return;
  const generation = ++squareOAuthLoadGeneration;
  try {
    const settings = await api("/api/settings/square/oauth-app");
    if (generation === squareOAuthLoadGeneration) renderSquareOAuthSettings(settings);
  } catch (err) {
    if (generation !== squareOAuthLoadGeneration) return;
    squareOAuthSettings = null;
    $("#square-active-connection").textContent = "Square connection status unavailable";
    $("#square-active-detail").textContent = "Reopen Settings to try loading the saved configuration again.";
    $("#square-oauth-saved-status").textContent = "Could not load saved application details.";
    $("#square-oauth-next-step").textContent = "Reload the saved configuration before signing in.";
    $("#square-oauth-connect").disabled = true;
    $("#square-oauth-save").disabled = true;
    squareOAuthMessage(err.message, "error");
  }
}

for (const id of ["#square-oauth-client-id", "#square-oauth-secret", "#square-oauth-env"]) {
  $(id).addEventListener("input", () => {
    squareOAuthDirty = !squareOAuthSettings
      || $("#square-oauth-client-id").value.trim() !== squareOAuthSettings.client_id
      || $("#square-oauth-env").value !== squareOAuthSettings.environment
      || $("#square-oauth-secret").value.length > 0;
    squareOAuthReturnFeedback = null;
    squareOAuthMessage("");
    squareOAuthSignInMessage("");
    updateSquareOAuthControls();
  });
}

$("#square-oauth-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (squareOAuthBusy) return;
  squareOAuthBusy = true;
  squareOAuthReturnFeedback = null;
  squareOAuthSignInMessage("");
  message("", "");
  ++squareOAuthLoadGeneration; // A slow pre-save read must not restore old details.
  updateSquareOAuthControls();
  squareOAuthMessage("Saving application credentials…");
  try {
    const settings = await api("/api/settings/square/oauth-app", {
      method: "PUT",
      body: JSON.stringify({
        client_id: $("#square-oauth-client-id").value.trim(),
        client_secret: $("#square-oauth-secret").value.trim(),
        environment: $("#square-oauth-env").value,
      }),
    });
    $("#square-oauth-secret").value = "";
    squareOAuthDirty = false;
    renderSquareOAuthSettings(settings);
    squareOAuthMessage(
      `${squareEnvironmentLabel(settings.environment)} application credentials saved. Your active connection is shown above.`,
      "ok",
    );
  } catch (err) {
    squareOAuthMessage(`Credentials were not saved. ${err.message}`, "error");
  } finally {
    squareOAuthBusy = false;
    updateSquareOAuthControls();
  }
});

$("#square-oauth-connect").addEventListener("click", () => {
  if (!squareOAuthSettings || squareOAuthBusy || !squareOAuthView(squareOAuthSettings, squareOAuthDirty).canConnect) return;
  $("#square-oauth-connect").disabled = true;
  $("#square-oauth-next-step").textContent = "Opening Square sign-in. Return here after approving read-only access to finish connecting.";
  window.location.href = "/oauth/square/start";
});

$("#square-oauth-switch-confirm").addEventListener("click", async () => {
  try {
    const result = await api("/api/settings/square/oauth-switch/confirm", {
      method: "POST",
    });
    squareOAuthReturnFeedback = null;
    squareOAuthSignInMessage("Square account switch completed. Map this account's cameras below.", "ok");
    $("#square-oauth-switch-warning").hidden = true;
    squareAccountRevision = result.account_revision || "";
    lastTransactionPayload = null;
    renderTransactions([]);
    void loadTransactions({ reset: true });
    void loadSettingsView();
    message(
      result.evidence_cleanup_pending
        ? "Square account switched. Old evidence cleanup will retry automatically."
        : "Square account switched; map this account's POS cameras and configure its webhook.",
      "ok",
    );
  } catch (err) {
    squareOAuthReturnFeedback = null;
    squareOAuthSignInMessage(err.message, "error");
    void loadSquareOAuthSettings();
    message(err.message, "error");
  }
});

$("#square-oauth-switch-cancel").addEventListener("click", async () => {
  try {
    await api("/api/settings/square/oauth-switch", { method: "DELETE" });
    squareOAuthReturnFeedback = null;
    $("#square-oauth-switch-warning").hidden = true;
    squareOAuthSignInMessage("Kept the current Square connection. Saved application credentials are still available.");
    void loadSquareOAuthSettings();
    message("Kept the current Square account.", "");
  } catch (err) {
    squareOAuthSignInMessage(err.message, "error");
    message(err.message, "error");
  }
});

$("#square-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const webhookFields = squareWebhookRequestFields(
      $("#square-webhook-key"),
      $("#square-webhook-url"),
      $("#square-clear-webhook"),
    );
    const result = await api("/api/settings/square", {
      method: "PUT",
      body: JSON.stringify({
        access_token: $("#square-token").value.trim(),
        environment: $("#square-env").value,
        ...webhookFields,
        confirm_account_switch: $("#square-confirm-account-switch").checked,
        account_switch_confirmation_token: squareAccountSwitchConfirmationToken,
      }),
    });
    $("#square-token").value = "";
    resetSquareWebhookFields(
      $("#square-webhook-key"),
      $("#square-webhook-url"),
      $("#square-clear-webhook"),
    );
    $("#square-confirm-account-switch").checked = false;
    $("#square-account-switch-warning").hidden = true;
    squareAccountSwitchConfirmationToken = "";
    squareAccountRevision = result.account_revision || "";
    const switched = result.account_switched
      ? result.evidence_cleanup_pending
        ? " Previous account data was disconnected. Orphan thumbnail cleanup will retry automatically."
        : result.webhook_configured
          ? " Previous account data was erased."
          : " Previous account data and saved webhook credentials were erased; configure this account's webhook to restore live updates."
      : "";
    message(
      `Connected to Square (${result.locations.length} locations).${switched}`,
      "ok",
    );
    if (result.account_switched) {
      lastTransactionPayload = null;
      renderTransactions([]);
      void loadTransactions({ reset: true });
    }
    loadSettingsView();
  } catch (err) {
    if (err.code === "square_account_switch_confirmation_required") {
      squareAccountSwitchConfirmationToken = err.confirmationToken || "";
      $("#square-confirm-account-switch").checked = false;
      $("#square-account-switch-warning").hidden = false;
      $("#square-confirm-account-switch").focus();
    }
    message(err.message, "error");
  }
});

function setConnStatus(id, state, text) {
  const el = $(id);
  el.hidden = false;
  el.className = `conn-status ${state}`;
  el.querySelector(".conn-text").textContent = text;
}

async function fetchConnectionStatus(loadStatus) {
  try {
    return { health: await loadStatus(), error: null };
  } catch (err) {
    return { health: null, error: err };
  }
}

function renderConnectionStatus(id, result) {
  if (result.error) {
    setConnStatus(id, "bad", result.error.message);
  } else if (!result.health.configured) {
    setConnStatus(id, "", "Not connected");
  } else if (result.health.ok) {
    setConnStatus(id, "ok", result.health.detail);
  } else {
    setConnStatus(id, "bad", result.health.detail);
  }
}

function createConnectionStatusRefresher(id, loadStatus) {
  return createLatestStatusRefresher(
    () => {
      setConnStatus(id, "checking", "Checking…");
      return fetchConnectionStatus(loadStatus);
    },
    (result) => renderConnectionStatus(id, result),
  );
}

const refreshProtectStatus = createConnectionStatusRefresher(
  "#protect-status",
  () => api("/api/health/protect"),
);
const refreshSquareStatus = createConnectionStatusRefresher(
  "#square-status",
  () => api("/api/health/square"),
);

async function fetchSettingsView() {
  void loadSquareOAuthSettings();
  // Clear any previous console's rows/preview before the provider reads so a
  // switch never leaves stale evidence on screen while data loads.
  clearProtectConsoleView(
    $("#mapping-rows"),
    $("#save-mapping"),
    $("#camera-preview-wrap"),
    $("#camera-preview"),
  );
  clearProtectAlarmSettingsView();
  clearProtectMotionSettingsView();
  // Each indicator has its own latest-response guard, so a slow previous
  // health request cannot overwrite the result of a newer settings load.
  void refreshSquareStatus();
  void refreshProtectStatus();
  void loadThumbnailStorageSettings().catch(() => {});
  return fetchMappingData();
}

async function fetchMappingData() {
  let cameras = [], locations = [], mappings = [], devices = [];
  let alarmSettings = null;
  let motionSettings = null;
  let locationRevision = null;
  let cameraGeneration = null;
  let alarmGeneration = null;
  let motionGeneration = null;
  let mappingRevision = "";
  let mappingGeneration = "";
  loadDeepLinkSettings();
  try {
    const result = await api("/api/cameras", { includeResponse: true });
    cameras = result.data;
    cameraGeneration =
      result.response.headers.get("x-protect-console-generation") || "";
  } catch { /* Protect not configured yet */ }
  try {
    const result = await api(
      "/api/settings/protect/alarm",
      { includeResponse: true },
    );
    alarmSettings = result.data;
    alarmGeneration =
      result.response.headers.get("x-protect-console-generation") || "";
  } catch { /* Transaction flags not configured yet */ }
  try {
    const result = await api(
      "/api/settings/protect/motion-webhook",
      { includeResponse: true },
    );
    motionSettings = result.data;
    motionGeneration =
      result.response.headers.get("x-protect-console-generation") || "";
  } catch { /* Motion webhook not configured yet */ }
  try {
    const result = await api("/api/locations", { includeResponse: true });
    locations = result.data;
    locationRevision =
      result.response.headers.get("x-square-account-revision") || "";
  } catch { /* Square not configured yet */ }
  try { devices = await api("/api/pos-devices"); } catch { /* No observed devices yet */ }
  try {
    const result = await api("/api/camera-mapping", { includeResponse: true });
    mappings = result.data;
    mappingGeneration =
      result.response.headers.get("x-protect-console-generation") || "";
    mappingRevision =
      result.response.headers.get("x-square-account-revision") || "";
  } catch { return null; }
  return {
    cameras, locations, mappings, devices, alarmSettings, motionSettings,
    cameraGeneration, alarmGeneration, motionGeneration, locationRevision,
    mappingGeneration, mappingRevision,
  };
}


function buildMappingRows(container, data) {
  const { cameras, locations, mappings, devices } = data;
  container.textContent = "";
  if (!cameras.length || !locations.length) {
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = "Connect both UniFi Protect and Square above to choose the POS camera.";
    container.appendChild(p);
    return false;
  }
  const mappingKey = (locationId, deviceId = "") =>
    JSON.stringify([locationId, deviceId || ""]);
  const current = new Map(mappings.map((m) => [
    mappingKey(m.location_id, m.device_id),
    m.camera_id,
  ]));
  const devicesByLocation = new Map();
  for (const device of devices) {
    if (!devicesByLocation.has(device.location_id))
      devicesByLocation.set(device.location_id, []);
    devicesByLocation.get(device.location_id).push(device);
  }

  for (const loc of locations) {
    const observed = devicesByLocation.get(loc.id) || [];
    const targets = [
      { device_id: "", device_name: "" },
      ...observed,
    ];
    for (const target of targets) {
      const row = document.createElement("div");
      row.className = "mapping-row";
      const label = document.createElement("label");
      label.className = "loc";
      const locationName = loc.name || loc.id;
      if (target.device_id) {
        label.textContent = `${locationName} — ${target.device_name || target.device_id}`;
      } else if (observed.length) {
        label.textContent = `${locationName} — Other devices (fallback)`;
      } else {
        label.textContent = locationName;
      }
      const select = document.createElement("select");
      select.id = cameraMappingSelectId(
        container.id,
        loc.id,
        target.device_id,
      );
      label.htmlFor = select.id;
      select.dataset.locationId = loc.id;
      select.dataset.deviceId = target.device_id || "";
      select.dataset.deviceName = target.device_name || "";
      const none = document.createElement("option");
      none.value = "";
      none.textContent = "— no camera —";
      select.appendChild(none);
      for (const cam of cameras) {
        const opt = document.createElement("option");
        opt.value = cam.id;
        opt.textContent = cam.name;
        if (current.get(mappingKey(loc.id, target.device_id)) === cam.id)
          opt.selected = true;
        select.appendChild(opt);
      }
      select.addEventListener("change", () => previewCamera(select.value));
      row.appendChild(label);
      row.appendChild(select);
      container.appendChild(row);
    }
  }
  return true;
}

function collectMappings(container) {
  const mappings = [];
  for (const select of container.querySelectorAll("select")) {
    if (!select.value) continue;
    mappings.push({
      location_id: select.dataset.locationId,
      device_id: select.dataset.deviceId || "",
      device_name: select.dataset.deviceName || "",
      camera_id: select.value,
      camera_name: select.options[select.selectedIndex].textContent,
    });
  }
  return mappings;
}

let settingsSnapshotRetriesRemaining = 1;

function renderSettingsView(settings) {
  const rows = $("#mapping-rows");
  const saveButton = $("#save-mapping");
  if (settings === null) return;
  if (!settingsSnapshotsMatch(settings)) {
    // A provider switch landed between the individual reads; the snapshots
    // describe two different accounts/consoles and must not be mixed.
    if (settingsSnapshotMismatchAction(settingsSnapshotRetriesRemaining) === "retry") {
      settingsSnapshotRetriesRemaining -= 1;
      void loadSettingsView();
      return;
    }
    const hint = document.createElement("p");
    hint.className = "hint";
    hint.textContent =
      "Provider settings kept changing while this page loaded. Reload the page to try again.";
    rows.appendChild(hint);
    return;
  }
  settingsSnapshotRetriesRemaining = 1;
  // Only the winning (latest) coherent load publishes the tokens used to
  // fence camera-mapping saves against a concurrent account/console switch.
  squareAccountRevision = settings.mappingRevision || "";
  cameraMappingGeneration = settings.mappingGeneration || "";
  renderProtectAlarmSettings(settings.alarmSettings);
  motionSettingsCameras = settings.cameras;
  renderProtectMotionSettings(settings.motionSettings, motionSettingsCameras);
  const usable = buildMappingRows(rows, settings);
  saveButton.hidden = !usable;
}

const loadSettingsView = createLatestSettingsLoader(
  fetchSettingsView,
  renderSettingsView,
);

function previewCamera(cameraId) {
  const wrap = $("#camera-preview-wrap");
  if (!cameraId) { wrap.hidden = true; return; }
  wrap.hidden = false;
  $("#camera-preview").src = `/api/camera-preview/${encodeURIComponent(cameraId)}?t=${Date.now()}`;
}

$("#save-mapping").addEventListener("click", async () => {
  const mappings = collectMappings($("#mapping-rows"));
  try {
    await api("/api/camera-mapping", {
      method: "PUT",
      headers: {
        "X-Square-Account-Revision": squareAccountRevision,
        "X-Protect-Console-Generation": cameraMappingGeneration,
      },
      body: JSON.stringify({ mappings }),
    });
    message("Camera selection saved.", "ok");
  } catch (err) {
    message(err.message, "error");
  }
});

// ---------------------------------------------------------------- transactions

function transactionRefreshAllowed() {
  // Refresh whenever the operator is logged in and the browser tab is
  // visible — including while the Settings section is open — so the feed is
  // always current the moment they switch back. Paging into history
  // (offset > 0) still pauses refresh so rows cannot shift underfoot.
  return document.visibilityState === "visible" &&
    !$("#nav").hidden && transactionOffset === 0;
}

function refreshTransactionsIfVisible() {
  // Offset pages would shift when new sales arrive. Keep older pages stable;
  // returning to the newest page resumes the normal live refresh.
  if (transactionRefreshAllowed()) {
    void loadTransactions({ reset: true, background: true });
  }
  if (document.visibilityState === "visible" && !$("#nav").hidden) {
    void loadMotionAlerts();
    if (isAdmin(currentUser) && !$("#view-settings").hidden) {
      void refreshProtectMotionLastEvent();
    }
  }
}

function startTransactionRefresh() {
  if (transactionRefreshTimer !== null) return;
  transactionRefreshTimer = window.setInterval(
    refreshTransactionsIfVisible,
    TRANSACTION_REFRESH_MS,
  );
}

function stopTransactionRefresh() {
  if (transactionRefreshTimer === null) return;
  window.clearInterval(transactionRefreshTimer);
  transactionRefreshTimer = null;
}

document.addEventListener("visibilitychange", refreshTransactionsIfVisible);

function updateTransactionPagination(loading = false) {
  $("#txn-prev").disabled = loading || transactionOffset === 0;
  $("#txn-next").disabled = loading || !transactionHasNext;
  const status = $("#txn-page-status");
  if (loading) {
    status.textContent = "Loading transaction page…";
  } else if (!transactionPageCount) {
    status.textContent = "No transactions to show";
  } else {
    const first = transactionOffset + 1;
    const last = transactionOffset + transactionPageCount;
    const oldest = transactionHasNext ? "" : " · oldest reached";
    const paused = transactionOffset > 0 ? " · auto-refresh paused" : "";
    const noun = transactionFiltersActive(transactionFilters)
      ? "matches"
      : "transactions";
    status.textContent = `Showing ${noun} ${first}–${last}${oldest}${paused}`;
  }
}

function protectTimelineLink(txn, content) {
  const link = document.createElement("a");
  link.className = "thumbnail-link";
  link.href = txn.deep_link;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.setAttribute(
    "aria-label",
    `Open UniFi Protect footage for transaction at ${new Date(txn.ts_ms).toLocaleString()}`,
  );
  link.title = "Open UniFi Protect timeline at this moment";
  link.appendChild(content);
  return link;
}

function clipNoteElement(txn) {
  const state = transactionNoteState(txn);
  if (!state.note && !isAdmin(currentUser)) return null;
  const note = document.createElement("div");
  note.className = "clip-note";
  let title = null;
  let text = null;
  function renderNoteText(value) {
    if (!value) {
      if (title) title.remove();
      if (text) text.remove();
      title = null;
      text = null;
      return;
    }
    if (!title) {
      title = document.createElement("strong");
      title.textContent = "Clip note";
      note.prepend(title);
    }
    if (!text) {
      text = document.createElement("p");
      title.after(text);
    }
    text.textContent = value;
  }
  renderNoteText(state.note);
  if (!isAdmin(currentUser)) return note;

  const editor = document.createElement("details");
  editor.className = "clip-note-editor";
  const summary = document.createElement("summary");
  summary.textContent = state.note ? "Edit clip note" : "Add clip note";
  const form = document.createElement("form");
  form.className = "clip-note-form";
  const label = document.createElement("label");
  label.textContent = "Clip note";
  const textarea = document.createElement("textarea");
  textarea.value = state.note;
  textarea.maxLength = MAX_TRANSACTION_NOTE_LENGTH;
  textarea.placeholder = "Add a searchable note…";
  textarea.spellcheck = true;
  label.appendChild(textarea);
  const submit = document.createElement("button");
  submit.type = "submit";
  submit.textContent = "Save note";
  form.append(label, submit);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    let body;
    try {
      body = transactionNoteUpdate(textarea.value, state.revision);
    } catch (error) {
      message(error.message, "error");
      return;
    }
    submit.disabled = true;
    try {
      const result = await api(
        `/api/transactions/${encodeURIComponent(txn.id)}/note`,
        {
          method: "PUT",
          body: JSON.stringify(body),
        },
      );
      txn.note = result.note;
      txn.note_revision = result.note_revision;
      state.note = result.note;
      state.revision = result.note_revision;
      renderNoteText(result.note);
      summary.textContent = result.note ? "Edit clip note" : "Add clip note";
      editor.open = false;
      transactionSnapshot = null;
      lastTransactionPayload = null;
      message("Clip note saved.", "ok");
      await loadTransactions({ offset: transactionOffset });
    } catch (error) {
      if (error.status === 409) {
        transactionSnapshot = null;
        lastTransactionPayload = null;
        void loadTransactions({ offset: transactionOffset });
      }
      message(error.message, "error");
    } finally {
      submit.disabled = false;
    }
  });
  editor.append(summary, form);
  note.appendChild(editor);
  return note;
}

function renderTransactions(
  txns,
  filtered = transactionFiltersActive(transactionFilters),
) {
  const list = $("#txn-list");
  list.textContent = "";
  if (!txns.length) {
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = filtered
      ? "No transactions match these filters."
      : "No transactions yet. Connect Square, then press “Sync now”.";
    list.appendChild(p);
    return;
  }
  for (const txn of txns) {
    const row = document.createElement("div");
    row.className = "txn";

    let thumb;
    if (txn.thumbnail_url) {
      const image = document.createElement("img");
      image.className = "thumb";
      image.src = txn.thumbnail_url;
      image.alt = "POS camera at time of transaction";
      if (txn.deep_link) {
        thumb = protectTimelineLink(txn, image);
      } else {
        thumb = image;
      }
    } else {
      thumb = document.createElement("div");
      thumb.className = "thumb placeholder";
      const thumbnailLabels = {
        unmapped: "camera not mapped",
        queued: "footage queued",
        retrying: "capture retrying",
        expired: "thumbnail expired",
      };
      thumb.textContent = thumbnailLabels[txn.thumbnail_status] || "no footage";
      if (txn.deep_link) {
        thumb = protectTimelineLink(txn, thumb);
      }
    }

    const amount = document.createElement("div");
    amount.className = "amount";
    amount.textContent = formatAmount(txn.amount, txn.currency);

    const meta = document.createElement("div");
    meta.className = "txn-details";
    const when = document.createElement("div");
    when.className = "meta";
    when.textContent = new Date(txn.ts_ms).toLocaleString();
    const card = document.createElement("div");
    card.className = "meta";
    card.textContent = txn.card_last4 ? `Card •••• ${txn.card_last4}` : "";
    const source = document.createElement("div");
    source.className = "meta";
    const deviceLabel = txn.device_name && txn.device_id
      ? `${txn.device_name} (${txn.device_id})`
      : txn.device_name || txn.device_id;
    source.textContent = [
      deviceLabel,
      txn.location_id,
    ].filter(Boolean).join(" · ");
    const transactionId = document.createElement("div");
    transactionId.className = "meta transaction-id";
    transactionId.textContent = `ID ${txn.id}`;
    const status = document.createElement("div");
    status.className = "status";
    status.textContent = txn.status;
    const refundStatus = renderRefundStatus(document, txn);
    const protectFlag = protectFlagDelivery(txn);
    meta.appendChild(when);
    meta.appendChild(card);
    meta.appendChild(source);
    meta.appendChild(transactionId);
    meta.appendChild(status);
    if (refundStatus) meta.appendChild(refundStatus);
    if (protectFlag.deliveredAtMs !== null) {
      const flag = document.createElement("div");
      flag.className = "meta protect-flag-delivery";
      const offset = formatSignedSeconds(protectFlag.offsetMs);
      flag.textContent = offset
        ? `Protect flag accepted · ${offset} from transaction`
        : "Protect flag accepted";
      flag.title = new Date(protectFlag.deliveredAtMs).toLocaleString();
      meta.appendChild(flag);
    }
    const clipNote = clipNoteElement(txn);
    if (clipNote) meta.appendChild(clipNote);

    row.appendChild(thumb);
    row.appendChild(amount);
    row.appendChild(meta);
    list.appendChild(row);
  }
}

function renderMotionAlerts(payload) {
  const configured = payload && payload.configured === true;
  const panel = $("#motion-alerts-panel");
  panel.hidden = !configured;
  const list = $("#motion-alert-list");
  list.textContent = "";
  if (!configured) return;
  const summary = payload.summary || {};
  const flagged = Number(summary.flagged) || 0;
  const pending = Number(summary.pending) || 0;
  $("#motion-alert-summary").textContent =
    `${flagged} flagged · ${pending} pending`;
  const events = Array.isArray(payload.events)
    ? payload.events.map(protectMotionAlert)
    : [];
  if (!events.length) {
    const empty = document.createElement("p");
    empty.className = "hint";
    empty.textContent = "No unmatched motion events.";
    list.appendChild(empty);
    return;
  }
  for (const event of events) {
    const row = document.createElement("article");
    row.className = `motion-alert ${event.state}`;
    const heading = document.createElement("div");
    heading.className = "motion-alert-heading";
    const camera = document.createElement("strong");
    camera.textContent = event.camera_name || event.camera_id || "Protect camera";
    const state = document.createElement("span");
    state.className = "motion-alert-state";
    state.textContent = protectMotionStateText(event);
    heading.append(camera, state);
    const detail = document.createElement("p");
    detail.className = "hint";
    const matchWindow = Math.round((Number(event.match_window_ms) || 0) / 1000);
    detail.textContent =
      `${new Date(event.event_ts_ms).toLocaleString()} · ±${matchWindow} second match window`;
    row.append(heading, detail);
    if (event.alarm_name) {
      const alarm = document.createElement("p");
      alarm.className = "hint";
      alarm.textContent = `Protect alarm: ${event.alarm_name}`;
      row.appendChild(alarm);
    }
    if (event.deep_link) {
      const link = document.createElement("a");
      link.href = event.deep_link;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = "Open Protect footage";
      link.setAttribute(
        "aria-label",
        `Open Protect footage for motion at ${new Date(event.event_ts_ms).toLocaleString()}`,
      );
      row.appendChild(link);
    }
    list.appendChild(row);
  }
}

async function loadMotionAlerts() {
  const generation = ++motionAlertLoadGeneration;
  try {
    const payload = await api("/api/motion-alerts?limit=50");
    if (generation === motionAlertLoadGeneration) renderMotionAlerts(payload);
  } catch (error) {
    if (generation === motionAlertLoadGeneration && !isSessionExpiredError(error)) {
      // Transaction and dashboard errors remain the primary global status.
      $("#motion-alerts-panel").hidden = true;
    }
  }
}

function setTile(name, state, value, hint) {
  const tile = document.querySelector(`.tile[data-tile="${name}"]`);
  tile.className = `tile ${state}`;
  tile.querySelector(".tile-value").textContent = value;
  tile.querySelector(".tile-hint").textContent = hint || "";
}

let dashboardTimer = null;

async function fetchDashboardStatus() {
  try {
    return await api("/api/dashboard");
  } catch {
    return null;
  }
}

function renderDashboard(data) {
  if (data === null) return;
  $("#dashboard-tiles").hidden = false;

  const conn = (info, fixHint) => {
    if (!info.configured) return ["idle", "Not connected", fixHint];
    if (info.ok) return ["ok", info.detail, ""];
    return ["bad", "Problem", info.detail];
  };
  setTile("protect", ...conn(data.protect, "Connect it in Settings"));
  setTile("square", ...conn(data.square, "Connect it in Settings"));

  if (!data.webhook.configured) {
    setTile("webhook", "idle", "Not configured",
      "Optional: real-time sales via Settings; polling still syncs every minute");
  } else if (data.webhook.last_payment_ms || data.webhook.last_event_ms) {
    const lastPayment = Boolean(data.webhook.last_payment_ms);
    const eventTime = data.webhook.last_payment_ms || data.webhook.last_event_ms;
    const minutes = Math.max(0, Math.round((Date.now() - eventTime) / 60000));
    const age = minutes < 1 ? "just now" : `${minutes} min ago`;
    const eventLabel = lastPayment ? "Last payment" : "Last event";
    setTile(
      "webhook",
      "ok",
      `${eventLabel} ${age}`,
      webhookDeliveryHint(data.webhook),
    );
  } else {
    setTile("webhook", "idle", "Waiting for first event",
      "Check the Square webhook subscription if sales are not arriving");
  }

  if (!data.motion.configured) {
    setTile("motion", "idle", "Not configured", "Enable it in Settings");
  } else if (data.motion.flagged > 0) {
    setTile(
      "motion",
      "bad",
      `${data.motion.flagged} flagged`,
      `${data.motion.pending} event(s) still waiting for Square`,
    );
  } else if (data.motion.pending > 0) {
    setTile(
      "motion",
      "idle",
      `${data.motion.pending} pending`,
      "Waiting for Square before evaluating",
    );
  } else {
    setTile("motion", "ok", "No unmatched motion", data.motion.camera_name || "");
  }

  const transactionFlags = protectAlarmStatus(data.transaction_flags);
  const activeFlags = transactionFlags.pending + transactionFlags.inProgress;
  if (!transactionFlags.configured) {
    setTile(
      "transaction-flags",
      "idle",
      "Not configured",
      "Enable it in Protect settings",
    );
  } else if (activeFlags > 0) {
    setTile(
      "transaction-flags",
      "idle",
      `${activeFlags} pending`,
      `${transactionFlags.delivered} accepted by Protect`,
    );
  } else {
    setTile(
      "transaction-flags",
      "ok",
      `${transactionFlags.delivered} accepted`,
      transactionFlags.lastDeliveredAtMs === null
        ? "Waiting for the first completed transaction"
        : `Last ${new Date(transactionFlags.lastDeliveredAtMs).toLocaleString()}`,
    );
  }

  const pending = data.queues.thumbnails_pending + data.queues.alarms_pending;
  if (pending === 0) {
    setTile("queues", "ok", "All caught up", "");
  } else {
    setTile("queues", "idle", `${pending} pending`,
      `${data.queues.thumbnails_pending} thumbnail(s), ${data.queues.alarms_pending} alarm(s) retrying`);
  }
}

const refreshDashboard = createLatestStatusRefresher(
  fetchDashboardStatus,
  renderDashboard,
);

function startDashboardRefresh() {
  if (dashboardTimer !== null) return;
  refreshDashboard();
  dashboardTimer = window.setInterval(() => {
    if (document.visibilityState === "visible" && !$("#nav").hidden)
      refreshDashboard();
  }, 60000);
}

async function loadTransactions({
  reset = false,
  offset = transactionOffset,
  background = false,
} = {}) {
  const requestedOffset = reset ? 0 : Math.max(0, offset);
  if (transactionLoadInFlight) {
    // Coalesce refreshes but retain the latest requested page. In particular,
    // a sync reset cannot be lost behind an older in-flight page request.
    transactionPendingOffset = requestedOffset;
    return;
  }
  transactionLoadInFlight = true;
  const requestedFilters = transactionFilters;
  updateTransactionPagination(true);
  let page = null;
  let pageSnapshot = null;
  try {
    const queryBody = transactionQueryBody(requestedFilters, {
      limit: TRANSACTION_PAGE_SIZE + 1,
      offset: requestedOffset,
      snapshot: requestedOffset > 0 ? transactionSnapshot : null,
    });
    const result = await api("/api/transactions", {
      method: "POST",
      body: JSON.stringify(queryBody),
      includeResponse: true,
    });
    page = result.data;
    pageSnapshot = result.response.headers.get("x-transaction-snapshot");
  } catch (err) {
    if (err.status === 409 && requestedOffset > 0) {
      // Durable ordering snapshots are bounded. An expired page restarts at
      // the newest chronological view instead of mixing two generations.
      transactionSnapshot = null;
      transactionPendingOffset = 0;
      message("Transaction page refreshed to the newest results.", "");
    } else if (!background) {
      // Timer-driven refreshes stay quiet so a transient fetch error cannot
      // overwrite an unrelated status message (e.g. a settings save result).
      message(err.message, "error");
    }
  } finally {
    transactionLoadInFlight = false;
  }

  // Ignore a response when a newer page/reset request arrived while it was
  // loading. The queued request below becomes the only rendered result.
  if (page && transactionPendingOffset === null) {
    const txns = page.slice(0, TRANSACTION_PAGE_SIZE);
    if (!txns.length && requestedOffset > 0) {
      transactionPendingOffset = Math.max(0, requestedOffset - TRANSACTION_PAGE_SIZE);
    } else {
      transactionOffset = requestedOffset;
      transactionSnapshot = pageSnapshot;
      transactionHasNext = page.length > TRANSACTION_PAGE_SIZE;
      transactionPageCount = txns.length;
      $("#txn-last-updated").textContent =
        `Last updated ${new Date().toLocaleTimeString()}`;
      const payload = JSON.stringify({
        offset: transactionOffset,
        snapshot: transactionSnapshot,
        hasNext: transactionHasNext,
        filters: requestedFilters,
        transactions: txns,
      });
      if (payload !== lastTransactionPayload) {
        lastTransactionPayload = payload;
        renderTransactions(txns, transactionFiltersActive(requestedFilters));
      }
    }
  }
  updateTransactionPagination(false);

  if (transactionPendingOffset !== null) {
    const pendingOffset = transactionPendingOffset;
    transactionPendingOffset = null;
    void loadTransactions({ offset: pendingOffset });
  }
}

$("#txn-prev").addEventListener("click", () => {
  if (transactionLoadInFlight || transactionOffset === 0) return;
  void loadTransactions({
    offset: Math.max(0, transactionOffset - TRANSACTION_PAGE_SIZE),
  });
});

$("#txn-next").addEventListener("click", () => {
  if (transactionLoadInFlight || !transactionHasNext) return;
  void loadTransactions({ offset: transactionOffset + TRANSACTION_PAGE_SIZE });
});

function applyTransactionFilters(filters) {
  transactionFilters = filters;
  transactionOffset = 0;
  transactionSnapshot = null;
  transactionHasNext = false;
  transactionPageCount = 0;
  lastTransactionPayload = null;
  renderTransactions([], transactionFiltersActive(filters));
  updateTransactionPagination(false);
  void loadTransactions({ reset: true });
}

$("#txn-filter-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const nextFilters = normalizeTransactionFilters(
    $("#txn-query").value,
    $("#txn-status-filter").value,
  );
  if (nextFilters.query.length > TRANSACTION_QUERY_MAX_LENGTH) {
    message("Transaction search is limited to 64 characters.", "error");
    return;
  }
  applyTransactionFilters(nextFilters);
});

$("#txn-filter-clear").addEventListener("click", () => {
  $("#txn-query").value = "";
  $("#txn-status-filter").value = "";
  applyTransactionFilters(normalizeTransactionFilters("", ""));
  $("#txn-query").focus();
});

const syncNowButton = $("#sync-now");
syncNowButton.addEventListener("click", async () => {
  if (syncNowButton.disabled) return;
  syncNowButton.disabled = true;
  message("Syncing…", "");
  try {
    const result = await api("/api/sync", { method: "POST" });
    message(`Synced ${result.ingested} transactions.`, "ok");
    await loadTransactions({ reset: true });
  } catch (err) {
    message(err.message, "error");
  } finally {
    syncNowButton.disabled = false;
  }
});

// ---------------------------------------------------------------- setup wizard

const WIZARD_SKIP_KEY = "spi-wizard-skipped";

function showWizardStep(step) {
  show("#view-wizard", false);
  $("#nav").hidden = false;
  let activeStep = null;
  for (const el of document.querySelectorAll(".wiz-step")) {
    const active = el.dataset.step === String(step);
    el.hidden = !active;
    if (active) activeStep = el;
  }
  for (const dot of document.querySelectorAll(".wiz-dot")) {
    const dotStep = Number(dot.dataset.step);
    dot.className = "wiz-dot" +
      (dotStep < step ? " done" : dotStep === step ? " active" : "");
  }
  focusViewHeading(activeStep);
}

async function maybeStartWizard() {
  if (!isAdmin(currentUser)) return false;
  if (localStorage.getItem(WIZARD_SKIP_KEY) === "1") return false;
  let status;
  try {
    status = await api("/api/status");
  } catch {
    return false;
  }
  if (!status.protect_configured) {
    showWizardStep(1);
    return true;
  }
  if (!status.square_configured) {
    showWizardStep(2);
    return true;
  }
  if (!status.cameras_mapped) {
    const ok = await loadWizardMapping();
    if (ok) {
      showWizardStep(3);
      return true;
    }
  }
  return false;
}

async function loadWizardMapping() {
  const data = await fetchMappingData();
  if (data === null) return false;
  if (!settingsSnapshotsMatch(data)) {
    wizardSquareAccountRevision = "";
    wizardProtectConsoleGeneration = "";
    $("#wiz-mapping-rows").textContent = "";
    message("Provider settings changed while camera choices were loading. Try again.", "error");
    return false;
  }
  const usable = buildMappingRows($("#wiz-mapping-rows"), data);
  wizardSquareAccountRevision = usable ? data.mappingRevision || "" : "";
  wizardProtectConsoleGeneration = usable ? data.mappingGeneration || "" : "";
  return usable;
}

$("#wiz-protect-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const result = await api("/api/settings/protect", {
      method: "PUT",
      body: JSON.stringify({
        host: $("#wiz-protect-host").value.trim(),
        username: $("#wiz-protect-username").value.trim(),
        password: $("#wiz-protect-password").value,
        verify_ssl: false,
      }),
    });
    $("#wiz-protect-password").value = "";
    message(`Connected to UniFi Protect (${result.cameras} cameras found).`, "ok");
    showWizardStep(2);
  } catch (err) {
    message(err.message, "error");
  }
});

$("#wiz-square-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api("/api/settings/square", {
      method: "PUT",
      body: JSON.stringify({
        access_token: $("#wiz-square-token").value.trim(),
        environment: $("#wiz-square-env").value,
      }),
    });
    $("#wiz-square-token").value = "";
    message("Connected to Square.", "ok");
    if (await loadWizardMapping()) {
      showWizardStep(3);
    } else {
      showWizardStep(4);
    }
  } catch (err) {
    message(err.message, "error");
  }
});

$("#wiz-save-mapping").addEventListener("click", async () => {
  const mappings = collectMappings($("#wiz-mapping-rows"));
  try {
    await api("/api/camera-mapping", {
      method: "PUT",
      headers: {
        "X-Square-Account-Revision": wizardSquareAccountRevision,
        "X-Protect-Console-Generation": wizardProtectConsoleGeneration,
      },
      body: JSON.stringify({ mappings }),
    });
    message("Camera selection saved.", "ok");
    showWizardStep(4);
  } catch (err) {
    message(err.message, "error");
  }
});

$("#wiz-finish").addEventListener("click", () => {
  localStorage.setItem(WIZARD_SKIP_KEY, "1");
  enterApp();
});

$("#wiz-skip").addEventListener("click", (e) => {
  e.preventDefault();
  localStorage.setItem(WIZARD_SKIP_KEY, "1");
  enterApp();
  show("#view-settings");
});


boot();
