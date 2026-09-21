"use strict";

function squareOAuthResultFeedback(search) {
  const result = new URLSearchParams(search).get("square_oauth");
  if (result === "connected") {
    return {
      text: "Square sign-in complete. Your active connection is shown below.",
      kind: "ok",
    };
  }
  if (result === "denied") {
    return {
      text: "Square sign-in was canceled. Your existing connection is unchanged. Use Step 2 to try again.",
      kind: "",
    };
  }
  if (result === "invalid_state") {
    return {
      text: "This Square sign-in expired or could not be verified. Your existing connection is unchanged. Use Step 2 to start a new sign-in.",
      kind: "error",
    };
  }
  if (result === "switch_required") {
    return {
      text: "Square sign-in succeeded. Review the account-switch confirmation below to finish connecting.",
      kind: "",
    };
  }
  return null;
}

function squareEnvironmentLabel(environment) {
  return environment === "sandbox" ? "Sandbox" : "Production";
}

function squareOAuthView(settings, dirty = false) {
  const environment = squareEnvironmentLabel(settings.environment);
  const active = settings.active_environment;
  const activeLabel = squareEnvironmentLabel(active);
  const oauthActive = active === settings.environment && settings.active_authentication === "oauth";
  let nextStep;
  if (dirty) {
    nextStep = "You have unsaved changes. Save credentials in Step 1 before signing in.";
  } else if (settings.pending_environment) {
    nextStep = `${squareEnvironmentLabel(settings.pending_environment)} sign-in succeeded. Review the account-switch confirmation below to finish. Your active connection has not changed.`;
  } else if (!settings.configured) {
    nextStep = "Save your application credentials in Step 1 to enable Square sign-in.";
  } else if (oauthActive) {
    nextStep = `${environment} is already connected through Square sign-in. You can sign in again to renew authorization or choose another account.`;
  } else {
    nextStep = `${environment} application credentials are saved. Next, sign in to Square below to authorize read-only access. Saving credentials alone does not change the active connection.`;
  }
  return {
    activeTitle: active ? `Active connection: ${activeLabel}` : "No active Square connection",
    activeDetail: active
      ? `Configured to read ${active === "sandbox" ? "test transactions" : "live transactions"} using ${settings.active_authentication === "oauth" ? "Square sign-in" : "a manually entered access token"}.`
      : "Save credentials, then sign in to start reading transactions.",
    savedStatus: settings.configured
      ? `${environment} application credentials saved. The secret is stored securely and is never displayed.`
      : "No application credentials saved yet.",
    nextStep,
    connectLabel: `${oauthActive ? "Reconnect" : "Connect with"} ${environment} Square`,
    canConnect: settings.configured && !dirty && !settings.pending_environment,
  };
}

function squareOAuthCanKeepSecret(settings, clientId, environment) {
  return Boolean(settings && settings.secret_saved
    && settings.client_id === clientId.trim() && settings.environment === environment);
}

function squareWebhookRequestFields(keyInput, urlInput, clearInput) {
  const clearWebhook = clearInput.checked;
  return {
    webhook_signature_key: clearWebhook ? "" : keyInput.value.trim(),
    webhook_url: clearWebhook ? "" : urlInput.value.trim(),
    clear_webhook: clearWebhook,
  };
}

function resetSquareWebhookFields(keyInput, urlInput, clearInput) {
  keyInput.value = "";
  urlInput.value = "";
  clearInput.checked = false;
}

if (typeof module !== "undefined") {
  module.exports = {
    resetSquareWebhookFields,
    squareEnvironmentLabel,
    squareOAuthCanKeepSecret,
    squareOAuthResultFeedback,
    squareOAuthView,
    squareWebhookRequestFields,
  };
}
