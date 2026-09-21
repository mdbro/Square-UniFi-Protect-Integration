use std::{fs, path::PathBuf, process::Command};

use serde_json::{Value, json};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn source(path: &str) -> String {
    fs::read_to_string(root().join(path)).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn node_eval(module: &str, body: &str) -> Value {
    let module = root()
        .join("app/static")
        .join(module)
        .canonicalize()
        .unwrap();
    let module = serde_json::to_string(module.to_str().unwrap()).unwrap();
    let program = format!(
        r#"const m=require({module});
Promise.resolve((()=>{{{body}}})()).then(
  value=>process.stdout.write(JSON.stringify(value)),
  error=>{{console.error(error && error.stack || error);process.exit(1)}}
);"#
    );
    let output = Command::new("node")
        .arg("-e")
        .arg(program)
        .output()
        .unwrap_or_else(|error| panic!("Node is required for browser asset tests: {error}"));
    assert!(
        output.status.success(),
        "Node evaluation failed for {module}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid Node JSON for {module}: {error}: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn assert_before(text: &str, first: &str, second: &str) {
    let first_index = text
        .find(first)
        .unwrap_or_else(|| panic!("missing {first}"));
    let second_index = text
        .find(second)
        .unwrap_or_else(|| panic!("missing {second}"));
    assert!(
        first_index < second_index,
        "{first} must load before {second}"
    );
}

#[test]
fn boot_recovery_distinguishes_sessions_from_actionable_startup_failures() {
    let result = node_eval(
        "boot-recovery.js",
        r#"
const expired=m.sessionExpiredError("Log in again");
return {
  expired:m.isSessionExpiredError(expired),
  ordinary:m.isSessionExpiredError(new Error("offline")),
  explicit:m.bootFailureMessage(new Error("Server unavailable")),
  fallback:m.bootFailureMessage(null),
};"#,
    );
    assert_eq!(result["expired"], true);
    assert_eq!(result["ordinary"], false);
    assert!(
        result["explicit"]
            .as_str()
            .unwrap()
            .contains("Server unavailable.")
    );
    assert!(
        result["explicit"]
            .as_str()
            .unwrap()
            .contains("Check the server connection and logs")
    );
    assert!(
        result["fallback"]
            .as_str()
            .unwrap()
            .contains("Unexpected startup error.")
    );
}

#[test]
fn bootstrap_browser_transport_accepts_only_https_or_literal_loopback() {
    let result = node_eval(
        "bootstrap-form.js",
        r#"
const hosts=["localhost","LOCALHOST.","127.0.0.1","127.255.255.255","::1","[::1]","::ffff:127.0.0.1"];
const bad=["10.0.0.5","localhost.example","127.0.0.1.example","127.0.0.999",""];
return {
  good:hosts.map(m.isLoopbackBrowserHostname),
  bad:bad.map(m.isLoopbackBrowserHostname),
  remote:m.bootstrapTransportError({protocol:"http:",hostname:"10.0.0.5"}),
  local:m.bootstrapTransportError({protocol:"http:",hostname:"localhost"}),
  secure:m.bootstrapTransportError({protocol:"https:",hostname:"10.0.0.5"}),
};"#,
    );
    assert!(
        result["good"]
            .as_array()
            .unwrap()
            .iter()
            .all(|value| value == true)
    );
    assert!(
        result["bad"]
            .as_array()
            .unwrap()
            .iter()
            .all(|value| value == false)
    );
    assert!(
        result["remote"]
            .as_str()
            .unwrap()
            .contains("requires HTTPS")
    );
    assert_eq!(result["local"], "");
    assert_eq!(result["secure"], "");
}

#[test]
fn deep_link_form_trims_requests_and_discards_stale_async_loads() {
    let result = node_eval(
        "deep-link-form.js",
        r#"return (async()=>{
  const input={value:"  https://custom  "};
  const request=m.deepLinkSettingsRequest(input);
  const renderedInput={value:"",placeholder:""}; const status={textContent:""};
  m.applyDeepLinkSettings(renderedInput,status,{template:"",default_template:"https://default"});
  let resolveOld; const old=new Promise(done=>{resolveOld=done}); const rendered=[];
  let calls=0;
  const loader=m.createLatestDeepLinkSettingsLoader(
    ()=>++calls===1?old:Promise.resolve({template:"new"}),
    value=>rendered.push(value.template),
  );
  const first=loader(); const second=loader(); resolveOld({template:"old"});
  await Promise.all([first,second]);
  const invalidated=[]; let resolveThird;
  const third=m.createLatestDeepLinkSettingsLoader(
    ()=>new Promise(done=>{resolveThird=done}), value=>invalidated.push(value),
  );
  const pending=third(); third.invalidate(); resolveThird("stale"); await pending;
  return {request,renderedInput,status:status.textContent,rendered,invalidated};
})();"#,
    );
    assert_eq!(result["request"], json!({"template": "https://custom"}));
    assert_eq!(result["renderedInput"]["placeholder"], "https://default");
    assert!(
        result["status"]
            .as_str()
            .unwrap()
            .contains("built-in default")
    );
    assert_eq!(result["rendered"], json!(["new"]));
    assert_eq!(result["invalidated"], json!([]));
}

#[test]
fn audit_accounts_roles_and_notes_accept_only_bounded_server_shapes() {
    let audit = node_eval(
        "login-audit.js",
        r#"return m.loginAuditPage({events:[
 {id:2,user_id:1,username:"admin",role:"admin",client_ip:"10.0.0.1",logged_in_at:123.5},
 {id:0,user_id:1,username:"bad",role:"admin",client_ip:"x",logged_in_at:1},
 {id:3,user_id:1,username:"owner",role:"owner",client_ip:"x",logged_in_at:1}
],next_before_id:2});"#,
    );
    assert_eq!(audit["events"].as_array().unwrap().len(), 1);
    assert_eq!(audit["events"][0]["username"], "admin");
    assert_eq!(audit["nextBeforeId"], 2);

    let accounts = node_eval(
        "user-management.js",
        r#"return {
 errors:[m.passwordPairError("short","short"),m.passwordPairError("long-enough","different"),m.passwordPairError("long-enough","long-enough")],
 labels:[m.accountRoleLabel("admin"),m.accountRoleLabel("viewer"),m.accountRoleLabel("owner")],
 users:m.userAccounts({users:[
   {id:1,username:"admin",role:"admin",enabled:true,created_at:1,current:true},
   {id:2,username:"bad",role:"owner",enabled:true,created_at:1}
 ]})
};"#,
    );
    assert!(
        accounts["errors"][0]
            .as_str()
            .unwrap()
            .contains("at least 8")
    );
    assert!(
        accounts["errors"][1]
            .as_str()
            .unwrap()
            .contains("do not match")
    );
    assert_eq!(accounts["errors"][2], "");
    assert_eq!(
        accounts["labels"],
        json!(["Administrator", "View only", "Unknown role"])
    );
    assert_eq!(accounts["users"].as_array().unwrap().len(), 1);
    assert_eq!(accounts["users"][0]["current"], true);

    let roles = node_eval(
        "roles.js",
        r#"const admin=m.sessionUser({user:{username:"admin",role:"admin"}});
const viewer=m.sessionUser({username:"viewer",role:"viewer"});
const elements=[{hidden:true},{hidden:true}]; const identity={textContent:""};
return {admin,viewer,bad:m.sessionUser({username:"owner",role:"owner"}),isAdmin:m.applyRoleInterface(admin,elements,identity),hidden:elements.map(x=>x.hidden),label:identity.textContent};"#,
    );
    assert_eq!(roles["bad"], Value::Null);
    assert_eq!(roles["isAdmin"], true);
    assert_eq!(roles["hidden"], json!([false, false]));
    assert_eq!(roles["label"], "admin · Administrator");

    let notes = node_eval(
        "transaction-note.js",
        r#"const state=m.transactionNoteState({note:"hello",note_revision:3});
let longError="";let controlError="";let revisionError="";
try{m.transactionNoteUpdate("x".repeat(2001),0)}catch(e){longError=e.message}
try{m.transactionNoteUpdate("bad\u0000note",0)}catch(e){controlError=e.message}
try{m.transactionNoteUpdate("ok",-1)}catch(e){revisionError=e.message}
return {state,update:m.transactionNoteUpdate("line 1\nline 2",3),longError,controlError,revisionError,max:m.MAX_TRANSACTION_NOTE_LENGTH};"#,
    );
    assert_eq!(notes["state"], json!({"note": "hello", "revision": 3}));
    assert_eq!(
        notes["update"],
        json!({"note": "line 1\nline 2", "revision": 3})
    );
    assert_eq!(notes["max"], 2000);
    for key in ["longError", "controlError", "revisionError"] {
        assert!(!notes[key].as_str().unwrap().is_empty());
    }
}

#[test]
fn protect_alarm_normalizes_counts_and_formats_signed_frame_offsets() {
    let result = node_eval(
        "protect-alarm.js",
        r#"return {
 status:m.protectAlarmStatus({configured:true,trigger_id:"sale",pending:2,in_progress:-1,delivered:3,last_delivered_at_ms:123}),
 delivery:m.protectFlagDelivery({protect_flag_delivered_at_ms:5000,protect_flag_offset_ms:-1250}),
 formatted:[m.formatSignedSeconds(1250),m.formatSignedSeconds(-1250),m.formatSignedSeconds(0),m.formatSignedSeconds(null)]
};"#,
    );
    assert_eq!(result["status"]["pending"], 2);
    assert_eq!(result["status"]["inProgress"], 0);
    assert_eq!(
        result["delivery"],
        json!({"deliveredAtMs": 5000, "offsetMs": -1250})
    );
    assert_eq!(
        result["formatted"],
        json!(["+1.250s", "−1.250s", "0.000s", ""])
    );
}

#[test]
fn protect_console_helpers_fence_switches_and_provider_generations() {
    let result = node_eval(
        "protect-console-switch.js",
        r#"let published=0;
const coherent={cameraGeneration:"G2",alarmGeneration:"G2",motionGeneration:"G2",locationRevision:"R2",mappingGeneration:"G2",mappingRevision:"R2"};
const mismatch={...coherent,cameraGeneration:"G1"};
const mappingRows={textContent:"old"},save={hidden:false},preview={hidden:false},image={src:"old",removeAttribute(){this.src=""}};
m.clearProtectConsoleView(mappingRows,save,preview,image);
return {
 unchecked:m.protectConsoleSwitchTokenRequest({checked:false},{host:"h"}),
 checked:m.protectConsoleSwitchTokenRequest({checked:true},{host:"h",username:"u",password:"p",verify_ssl:true,api_key:"no"}),
 switched:m.protectConnectionMessage({cameras:2,alarm_configured:false,console_switched:true}),
 same:m.protectConnectionMessage({cameras:2,alarm_configured:true,console_switched:false}),
 ids:[m.cameraMappingSelectId("rows","LOC-1","DEV-2"),m.cameraMappingSelectId("rows","LOC","1-DEV-2"),m.cameraMappingSelectId("wizard","LOC-1","DEV-2")],
 latest:[m.publishLatestSettingsLoad(1,2,()=>published++),m.publishLatestSettingsLoad(2,2,()=>published++)],
 decisions:[m.publishCoherentSettingsLoad(2,2,mismatch,()=>published++),m.publishCoherentSettingsLoad(2,2,coherent,()=>published++),m.settingsSnapshotMismatchAction(1),m.settingsSnapshotMismatchAction(0)],
 published,cleared:[mappingRows.textContent,save.hidden,preview.hidden,image.src]
};"#,
    );
    assert_eq!(result["unchecked"], Value::Null);
    assert_eq!(
        result["checked"],
        json!({"host": "h", "username": "u", "password": "p", "verify_ssl": true})
    );
    assert!(
        result["switched"]
            .as_str()
            .unwrap()
            .contains("evidence were cleared")
    );
    assert!(!result["same"].as_str().unwrap().contains("cleared"));
    let ids = result["ids"].as_array().unwrap();
    assert!(ids[0] != ids[1] && ids[0] != ids[2]);
    assert_eq!(result["latest"], json!([false, true]));
    assert_eq!(
        result["decisions"],
        json!(["reload", "published", "retry", "show-reload"])
    );
    assert_eq!(result["published"], 2);
    assert_eq!(result["cleared"], json!(["", true, true, ""]));
}

#[test]
fn latest_async_renderers_discard_out_of_order_completions() {
    let result = node_eval(
        "settings-loader.js",
        r#"return (async()=>{
let resolveOld; const old=new Promise(done=>{resolveOld=done}); let calls=0; const rendered=[];
const load=m.createLatestSettingsLoader(()=>++calls===1?old:Promise.resolve("new"),value=>rendered.push(value));
const first=load(); const second=load(); resolveOld("old"); const outcomes=await Promise.all([first,second]);
let resolveStatus; const statusValues=[];
const status=m.createLatestStatusRefresher(()=>new Promise(done=>{resolveStatus=done}),value=>statusValues.push(value));
const pending=status(); resolveStatus("ok"); await pending;
return {rendered,outcomes,statusValues};
})();"#,
    );
    assert_eq!(result["rendered"], json!(["new"]));
    assert_eq!(result["outcomes"], json!([false, true]));
    assert_eq!(result["statusValues"], json!(["ok"]));
}

#[test]
fn protect_motion_uses_current_origin_bounded_settings_and_safe_state_labels() {
    let result = node_eval(
        "protect-motion.js",
        r#"const event=Date.UTC(2026,7,8,20,0,0);let crossOrigin="";
try{m.protectMotionWebhookUrl("https://app.lan","https://attacker.example/hook")}catch(e){crossOrigin=e.message}
return {
 urls:[m.protectMotionWebhookUrl("https://10.23.45.67:8000","/webhooks/protect/motion"),m.protectMotionWebhookUrl("https://app.lan:9443","/webhooks/protect/motion")],
 crossOrigin,
 settings:m.protectMotionSettings({enabled:true,camera_id:"counter",camera_name:"Counter",match_window_seconds:12,grace_seconds:75,retention_days:45,token_configured:true,last_event_ms:event}),
 request:m.protectMotionSettingsRequest({cameraId:"counter",matchWindowSeconds:"15",graceSeconds:"90",retentionDays:"30",rotateToken:true}),
 ages:[m.protectMotionReceiptStatus(event,event+90000),m.protectMotionReceiptStatus(event,event+7200000).relativeText,m.protectMotionReceiptStatus(null,event)],
 states:[m.protectMotionStateText({state:"pending"}),m.protectMotionStateText({state:"flagged"}),m.protectMotionStateText({state:"matched"}),m.protectMotionAlert({state:"unsafe"}).state]
};"#,
    );
    assert_eq!(
        result["urls"],
        json!([
            "https://10.23.45.67:8000/webhooks/protect/motion",
            "https://app.lan:9443/webhooks/protect/motion"
        ])
    );
    assert!(
        result["crossOrigin"]
            .as_str()
            .unwrap()
            .contains("this app origin")
    );
    assert_eq!(result["settings"]["webhookToken"], "");
    assert_eq!(result["request"]["grace_seconds"], 90);
    assert_eq!(result["ages"][0]["relativeText"], "1 minute ago");
    assert_eq!(result["ages"][1], "2 hours ago");
    assert_eq!(result["ages"][2]["received"], false);
    assert_eq!(
        result["states"],
        json!([
            "Waiting for Square",
            "No matching transaction",
            "Matched to transaction",
            "pending"
        ])
    );
}

#[test]
fn square_oauth_form_distinguishes_saved_credentials_from_the_active_connection() {
    let result = node_eval(
        "square-form.js",
        r#"
const saved={configured:true,client_id:"test-production-app",secret_saved:true,environment:"production",active_environment:"sandbox",active_authentication:"access_token",pending_environment:null};
return {
  saved:m.squareOAuthView(saved),
  dirty:m.squareOAuthView(saved,true),
  empty:m.squareOAuthView({...saved,configured:false,active_environment:null}),
  connected:m.squareOAuthView({...saved,active_environment:"production",active_authentication:"oauth"}),
  pending:m.squareOAuthView({...saved,pending_environment:"production"}),
  keepSecret:[m.squareOAuthCanKeepSecret(saved,"test-production-app","production"),m.squareOAuthCanKeepSecret(saved,"test-other-app","production"),m.squareOAuthCanKeepSecret(saved,"test-production-app","sandbox")],
  expired:m.squareOAuthResultFeedback("?square_oauth=invalid_state"),
};"#,
    );
    assert_eq!(result["saved"]["activeTitle"], "Active connection: Sandbox");
    assert!(
        result["saved"]["nextStep"]
            .as_str()
            .unwrap()
            .contains("Production application credentials are saved")
    );
    assert_eq!(result["saved"]["canConnect"], true);
    assert_eq!(result["dirty"]["canConnect"], false);
    assert_eq!(result["empty"]["canConnect"], false);
    assert_eq!(
        result["empty"]["activeTitle"],
        "No active Square connection"
    );
    assert_eq!(
        result["connected"]["activeTitle"],
        "Active connection: Production"
    );
    assert_eq!(
        result["connected"]["connectLabel"],
        "Reconnect Production Square"
    );
    assert_eq!(result["pending"]["canConnect"], false);
    assert!(
        result["pending"]["nextStep"]
            .as_str()
            .unwrap()
            .contains("confirmation")
    );
    assert_eq!(result["keepSecret"], json!([true, false, false]));
    assert_eq!(result["expired"]["kind"], "error");
    assert!(
        result["expired"]["text"]
            .as_str()
            .unwrap()
            .contains("existing connection is unchanged")
    );
}

#[test]
fn square_form_and_transaction_filters_clear_secrets_and_keep_queries_in_json() {
    let square = node_eval(
        "square-form.js",
        r#"const key={value:"  signature-key  "},url={value:"  https://example.test/hook  "},clear={checked:false};
const saved=m.squareWebhookRequestFields(key,url,clear);m.resetSquareWebhookFields(key,url,clear);const reset=[key.value,url.value,clear.checked];
clear.checked=true;key.value="stale";url.value="stale";
return {saved,reset,removed:m.squareWebhookRequestFields(key,url,clear),oauth:[m.squareOAuthResultFeedback("?square_oauth=connected"),m.squareOAuthResultFeedback("?square_oauth=denied"),m.squareOAuthResultFeedback("")]};"#,
    );
    assert_eq!(
        square["saved"],
        json!({"webhook_signature_key": "signature-key", "webhook_url": "https://example.test/hook", "clear_webhook": false})
    );
    assert_eq!(square["reset"], json!(["", "", false]));
    assert_eq!(square["removed"]["clear_webhook"], true);
    assert_eq!(square["removed"]["webhook_signature_key"], "");
    assert_eq!(square["oauth"][0]["kind"], "ok");
    assert_eq!(square["oauth"][2], Value::Null);

    let filters = node_eval(
        "transaction-filters.js",
        r#"const active=m.normalizeTransactionFilters("  PAY %_&42  ","COMPLETED");const empty=m.normalizeTransactionFilters("   ","");
return {active,body:m.transactionQueryBody(active,{limit:101,offset:100,snapshot:7}),isActive:m.transactionFiltersActive(active),emptyBody:m.transactionQueryBody(empty,{limit:51,offset:0}),emptyActive:m.transactionFiltersActive(empty),max:m.TRANSACTION_QUERY_MAX_LENGTH};"#,
    );
    assert_eq!(
        filters["active"],
        json!({"query": "PAY %_&42", "status": "COMPLETED"})
    );
    assert_eq!(filters["body"]["q"], "PAY %_&42");
    assert_eq!(filters["body"]["snapshot"], 7);
    assert_eq!(filters["isActive"], true);
    assert_eq!(filters["emptyBody"], json!({"limit": 51, "offset": 0}));
    assert_eq!(filters["emptyActive"], false);
    assert_eq!(filters["max"], 64);
}

#[test]
fn refund_helpers_render_accessible_partial_full_and_absent_states() {
    let result = node_eval(
        "format.js",
        r#"const doc={createElement:()=>({className:"",textContent:""})};
const partial=m.refundPresentation({amount:100,refunded_amount:25,currency:"USD"});
const full=m.renderRefundStatus(doc,{amount:100,refunded_amount:100,currency:"USD"});
return {partial,full,absent:[m.refundPresentation({amount:100,refunded_amount:0,currency:"USD"}),m.refundPresentation({amount:"100",refunded_amount:25,currency:"USD"})]};"#,
    );
    assert_eq!(result["partial"]["className"], "refund-status partial");
    assert!(
        result["partial"]["textContent"]
            .as_str()
            .unwrap()
            .contains("Partially refunded")
    );
    assert_eq!(result["full"]["className"], "refund-status full");
    assert!(
        result["full"]["textContent"]
            .as_str()
            .unwrap()
            .contains("Fully refunded")
    );
    assert_eq!(result["absent"], json!([null, null]));
}

#[test]
fn navigation_and_focus_helpers_preserve_accessibility_semantics() {
    let navigation = node_eval(
        "nav-view.js",
        r#"function button(view){const classes=new Set();const attrs=new Map();return {dataset:{view},classList:{contains:n=>classes.has(n),toggle(n,on){on?classes.add(n):classes.delete(n)}},getAttribute:n=>attrs.get(n)||null,setAttribute:(n,v)=>attrs.set(n,v),removeAttribute:n=>attrs.delete(n)}}
const tx={id:"view-transactions",hidden:true},settings={id:"view-settings",hidden:true},login={id:"view-login",hidden:true};const txb=button("transactions"),sb=button("settings");
const active=m.activateViewState([tx,settings,login],settings,[txb,sb]);
return {active,hidden:[tx.hidden,settings.hidden,login.hidden],classes:[txb.classList.contains("active"),sb.classList.contains("active")],current:[txb.getAttribute("aria-current"),sb.getAttribute("aria-current")],names:[m.navViewName(tx),m.navViewName(settings),m.navViewName(login)]};"#,
    );
    assert_eq!(navigation["active"], "settings");
    assert_eq!(navigation["hidden"], json!([true, false, true]));
    assert_eq!(navigation["classes"], json!([false, true]));
    assert_eq!(navigation["current"], json!([null, "page"]));
    assert_eq!(navigation["names"], json!(["transactions", "settings", ""]));

    let focus = node_eval(
        "view-focus.js",
        r#"let focused=0,removed=0,blur;const attrs=new Map();const heading={hasAttribute:n=>attrs.has(n),setAttribute:(n,v)=>attrs.set(n,v),getAttribute:n=>attrs.get(n),removeAttribute:n=>{attrs.delete(n);removed++},focus:()=>focused++,addEventListener:(name,cb)=>{if(name==="blur")blur=cb}};const container={querySelector:()=>heading};const ok=m.focusViewHeading(container);blur();return {ok,focused,removed,tabindex:attrs.get("tabindex")||null,missing:m.focusViewHeading({querySelector:()=>null}),invalid:m.focusViewHeading(null)};"#,
    );
    assert_eq!(
        focus,
        json!({"ok": true, "focused": 1, "removed": 1, "tabindex": null, "missing": false, "invalid": false})
    );
}

#[test]
fn webhook_delivery_copy_handles_milliseconds_seconds_minutes_and_clock_skew() {
    let result = node_eval(
        "webhook-delivery.js",
        r#"return {durations:[m.webhookDuration(125),m.webhookDuration(1250),m.webhookDuration(15000),m.webhookDuration(90000),m.webhookDuration("bad")],hints:[m.webhookDeliveryHint({last_delivery_lag_ms:1250,accepted_payment_count:2,duplicate_count:1}),m.webhookDeliveryHint({last_delivery_lag_ms:-5000,accepted_payment_count:1,duplicate_count:0}),m.webhookDeliveryHint(null)]};"#,
    );
    assert_eq!(
        result["durations"],
        json!(["125 ms", "1.25 s", "15.0 s", "1.5 min", ""])
    );
    assert!(
        result["hints"][0]
            .as_str()
            .unwrap()
            .contains("2 payment events accepted")
    );
    assert!(
        result["hints"][0]
            .as_str()
            .unwrap()
            .contains("1 duplicate ignored")
    );
    assert!(
        result["hints"][1]
            .as_str()
            .unwrap()
            .contains("Host clock was")
    );
    assert_eq!(result["hints"][2], "");
}

#[test]
fn helper_scripts_load_before_the_application_entrypoint() {
    let html = source("app/static/index.html");
    for helper in [
        "/bootstrap-form.js",
        "/boot-recovery.js",
        "/protect-console-switch.js",
        "/square-form.js",
        "/deep-link-form.js",
        "/protect-alarm.js",
        "/protect-motion.js",
        "/view-focus.js",
        "/settings-loader.js",
        "/nav-view.js",
        "/transaction-filters.js",
        "/transaction-note.js",
        "/webhook-delivery.js",
        "/roles.js",
        "/user-management.js",
        "/login-audit.js",
    ] {
        assert_before(&html, helper, "/app.js");
    }
}

#[test]
fn frontend_renders_provider_data_as_text_and_never_uses_inner_html() {
    let app = source("app/static/app.js");
    assert!(!app.contains("innerHTML"));
    for contract in [
        "camera.textContent = event.camera_name",
        "transactionId.textContent = `ID ${txn.id}`",
        "thumb.textContent = thumbnailLabels",
        "text.textContent = value",
    ] {
        assert!(
            app.contains(contract),
            "missing safe rendering contract: {contract}"
        );
    }
}

#[test]
fn transaction_search_sync_and_csv_actions_are_securely_wired() {
    let app = source("app/static/app.js");
    let html = source("app/static/index.html");
    let css = source("app/static/style.css");
    assert!(app.contains("transactionQueryBody(requestedFilters"));
    assert!(app.contains("api(\"/api/transactions\", {\n      method: \"POST\""));
    assert!(!app.contains("/api/transactions?"));
    assert!(app.contains("if (syncNowButton.disabled) return"));
    assert_before(
        &app,
        "syncNowButton.disabled = true",
        "syncNowButton.disabled = false",
    );
    assert!(html.contains("id=\"export-csv\" href=\"/api/transactions/export.csv\""));
    assert!(html.contains("download=\"square-protect-transactions.csv\""));
    assert!(css.contains("#export-csv:focus-visible"));
}

#[test]
fn thumbnail_controls_timeline_links_and_expired_states_remain_accessible() {
    let html = source("app/static/index.html");
    let app = source("app/static/app.js");
    let css = source("app/static/style.css");
    for field in [
        "id=\"thumbnail-jpeg-quality\" min=\"30\" max=\"95\"",
        "id=\"thumbnail-max-dimension\" min=\"320\" max=\"3840\"",
        "id=\"thumbnail-retention-days\" min=\"0\" max=\"3650\"",
        "id=\"thumbnail-max-storage-mib\" min=\"0\" max=\"1048576\"",
    ] {
        assert!(html.contains(field), "missing {field}");
    }
    assert!(html.contains("permanently remove only thumbnail JPEGs"));
    assert!(html.contains("Transaction details and UniFi Protect timeline links remain"));
    for label in [
        "unmapped: \"camera not mapped\"",
        "queued: \"footage queued\"",
        "retrying: \"capture retrying\"",
        "expired: \"thumbnail expired\"",
    ] {
        assert!(app.contains(label));
    }
    for link_contract in [
        "link.href = txn.deep_link",
        "link.target = \"_blank\"",
        "link.rel = \"noopener noreferrer\"",
        "\"aria-label\"",
    ] {
        assert!(app.contains(link_contract));
    }
    assert!(css.contains(".thumbnail-link:focus-visible"));
}

#[test]
fn mobile_layout_stacks_fixed_rows_without_breaking_desktop_sizes() {
    let css = source("app/static/style.css");
    let split = css
        .find("@media (max-width: 520px)")
        .expect("mobile media query");
    let (desktop, mobile) = css.split_at(split);
    for contract in [
        "flex-direction: column",
        "grid-template-columns: repeat(3, minmax(0, 1fr))",
        "nav[hidden] { display: none; }",
        "form, label, input, select, button { min-width: 0; max-width: 100%; }",
        ".mapping-row .loc { min-width: 0; width: 100%; }",
        ".mapping-row select { width: 100%; }",
        "aspect-ratio: 16 / 9",
        ".toolbar { flex-wrap: wrap",
    ] {
        assert!(
            mobile.contains(contract),
            "missing mobile contract: {contract}"
        );
    }
    assert!(desktop.contains(".mapping-row .loc { min-width: 280px"));
    assert!(desktop.contains("width: 160px; height: 90px"));
    assert!(desktop.contains("justify-content: space-between"));
}

fn hex_color_after(text: &str, selector: &str, from_end: bool) -> String {
    let start = if from_end {
        text.rfind(selector)
    } else {
        text.find(selector)
    }
    .unwrap_or_else(|| panic!("missing selector {selector}"));
    let rule = &text[start..text[start..].find('}').map(|end| start + end).unwrap()];
    let color = rule.find("color:").expect("color declaration");
    let hash = rule[color..].find('#').expect("hex color") + color;
    rule[hash..hash + 7].to_owned()
}

fn luminance(color: &str) -> f64 {
    let channels: Vec<_> = [1, 3, 5]
        .into_iter()
        .map(|index| u8::from_str_radix(&color[index..index + 2], 16).unwrap() as f64 / 255.0)
        .map(|channel| {
            if channel <= 0.04045 {
                channel / 12.92
            } else {
                ((channel + 0.055) / 1.055).powf(2.4)
            }
        })
        .collect();
    0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]
}

fn contrast(first: &str, second: &str) -> f64 {
    let (first, second) = (luminance(first), luminance(second));
    let (lighter, darker) = if first >= second {
        (first, second)
    } else {
        (second, first)
    };
    (lighter + 0.05) / (darker + 0.05)
}

#[test]
fn message_and_placeholder_colors_meet_wcag_contrast() {
    let css = source("app/static/style.css");
    let light_ok = hex_color_after(&css, "#message.ok", false);
    let dark_ok = hex_color_after(&css, "#message.ok", true);
    let dark_error = hex_color_after(&css, "#message.error", true);
    assert!(
        contrast(&light_ok, "#ffffff") >= 4.5,
        "light success {light_ok}"
    );
    assert!(
        contrast(&dark_ok, "#121212") >= 4.5,
        "dark success {dark_ok}"
    );
    assert!(
        contrast(&dark_error, "#121212") >= 4.5,
        "dark error {dark_error}"
    );

    let selector = ".txn .thumb.placeholder";
    let start = css.find(selector).unwrap();
    let rule = &css[start..start + css[start..].find('}').unwrap()];
    let opacity_start = rule.find("opacity:").unwrap() + "opacity:".len();
    let opacity: f64 = rule[opacity_start..]
        .trim_start()
        .split(';')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let text = 255.0 * (1.0 - opacity);
    let background = 255.0 * (1.0 - 0.18 * opacity);
    let gray = |channel: f64| format!("#{0:02x}{0:02x}{0:02x}", channel.round() as u8);
    assert!(contrast(&gray(text), &gray(background)) >= 4.5);
}
