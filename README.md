# Square × UniFi Protect Integration

This standalone companion app links **Square POS transactions** to **UniFi
Protect camera footage**. It approximates the transaction-to-video workflow of
UniFi Protect's native Shopify integration, but it does not install a Square
settings page or transaction feed inside the Protect application.

Every Square payment shows up in the companion feed with its timestamp, amount,
card details, and a thumbnail requested from the camera watching the POS.
Clicking the thumbnail uses a version-dependent deep link to open the Protect
timeline near that timestamp.

## Implemented companion features

- **Connect your Square account** — enter a Square access token in the companion
  app (production or sandbox); the integration verifies it against the Square
  API before saving.
- **Connect your UniFi Protect console** — local-account credentials for your
  UniFi OS console (Dream Machine, NVR, etc.), verified on save.
- **Choose the POS camera per register** — map each observed Square POS device
  to its own Protect camera, with per-location fallbacks and a live snapshot
  preview. Multi-register stores get the right footage for each terminal.
- **Trigger Protect alarms for completed sales (optional)** — use a Protect API
  key and matching Alarm Manager webhook trigger ID to run notifications or
  Protect automations whenever Square marks a payment completed. Delivery is
  at-least-once with durable state; sales completed before the feature is
  enabled are never replayed. Each transaction card shows when Protect accepted
  its flag and the measured delay from the Square transaction timestamp.
- **Transaction feed** — payments appear in the companion app with timestamp,
  tip-inclusive amount, partial or full refund totals, card last-4, status, and
  a camera thumbnail; the feed auto-refreshes while visible. Refund totals come
  from each Payment object's `refunded_money`, so no extra Square permission or
  refund API request is needed.
- **Click through to footage** — clicking a thumbnail uses the configured URL
  template to open the Protect timeline near the transaction timestamp.
- **Fast retail lookup** — search the local feed by transaction ID, card last-4,
  locally authored clip note, POS device/name, location ID, or status, and
  narrow it to a Square payment status. Searches use normalized local fields,
  do not retain new buyer data,
  and send lookup terms in an authenticated JSON body rather than a URL that
  ordinary web-server or proxy access logs may record.
- **Real-time + backfill** — a Square webhook receiver acknowledges deliveries
  immediately (HMAC-SHA256 signature verified) and captures footage
  asynchronously, while a background poller reconciles every Square location
  by update time. The dashboard reports measured Square-to-app delivery lag and
  safely ignores duplicate event IDs. Missed thumbnails persist in a durable
  retry queue with backoff, so a Protect outage never permanently loses evidence.
- **Bounded thumbnail storage** — optionally resize/re-encode new or existing
  JPEGs, expire thumbnails by age, and cap total thumbnail storage. Expiration
  removes only image bytes; transaction facts and Protect timeline links remain.
- **Role-bound sessions** — administrators can configure integrations and run
  manual syncs; view-only accounts can use the dashboard, transaction feed,
  CSV export, thumbnails, and footage links without changing configuration.
- **Local account management** — administrators can add administrator or
  view-only users and reset passwords from Settings. A reset atomically signs
  out every session belonging to that account.
- **Login history** — every successful login appends the username, role,
  server-observed client IP, and timestamp to an administrator-only audit log.
  Older entries remain available through cursor-based pagination.
- **Searchable clip notes** — administrators can add or clear a note on each
  transaction/footage card. View-only accounts can read notes, and the existing
  local search and CSV export include them.
- **Motion without a transaction** — a Protect-native motion zone can send an
  authenticated Alarm Manager webhook to the app. Motion waits through a
  configurable Square grace period, then becomes a visible flag when the same
  camera has no transaction inside the configured timestamp window.

## Protect integration boundary

As of July 2026, the [documented UniFi Protect API](https://developer.ui.com/protect)
does not expose a way for third-party applications to add a retail transaction
feed or credential screen inside Protect. Native Shopify-style placement would
therefore require a separate Ubiquiti partner/private integration contract.
Square credentials and transactions in this repository live in the companion
web app. The sale-alarm feature uses the official integration API
(`X-API-Key` + Alarm Manager webhook triggers) and is the supported way to
surface sale events inside Protect itself.

The repository's local-account login, recording-snapshot query, and playback
deep link are undocumented Protect interfaces. They have been verified against
a UNVR G2 on Protect 7.1.87 (a dedicated view-only local account is
sufficient for all of them), but they can change across Protect releases —
re-verify after major console updates. The default deep link matches the
URL Protect's own event links use on that version:
`https://{host}/protect/timelapse/{camera_id}?start={ts_ms}`.

## Quick start

**macOS:** double-click `Start Square Protect.command` in this folder. It sets
up the Rust build on first run, starts the app, and opens the dashboard in your
browser. Keep the Terminal window it opens in the background; closing it stops
the app.

**Linux or macOS (terminal):**

```bash
cargo run --locked --release
```

**Windows (PowerShell):**

```powershell
cargo run --locked --release
```

Install the current stable Rust toolchain from [rustup.rs](https://rustup.rs/)
if `cargo` is not already available. The server, provider clients, security
layer, SQLite store, synchronization engine, webhooks, TLS, thumbnail pipeline,
macOS menu-bar app, supported installers, and test harness are implemented in
Rust. Browser assets remain JavaScript and are behavior-tested by Rust tests
that invoke Node as the JavaScript engine.

The bundled runner binds only to `127.0.0.1` by default. On first start it
prints a generated one-time bootstrap secret in the server console. Copy that
secret, open `http://localhost:3546` on the same computer, and enter it with the
new admin password. Direct explicit loopback setup may use HTTP; every setup
still requires the one-time secret.

### First-time setup from another device

Configure TLS and a one-time bootstrap secret **before** exposing a new
installation on the network:

```bash
export SPI_TLS=1
export SPI_BOOTSTRAP_SECRET="$(openssl rand -base64 32)"
export SPI_HOST=0.0.0.0
cargo run --locked --release
```

Only after those settings are active, open `https://<server-ip>:3546` from the
other device, accept the one-time self-signed certificate warning, and enter
`SPI_BOOTSTRAP_SECRET` in **One-time bootstrap secret**. A wildcard or
non-loopback bind always requires the app's built-in TLS, even when a proxy
claims that the original request used HTTPS.

Then:

1. **Create the administrator account** (first run only). Its username is
   `admin`; upgraded installations keep their existing password and sessions.
2. **Settings → UniFi Protect console** — host/IP of your console plus a local
   Protect user's credentials (a dedicated view-only local user is recommended).
   To trigger an alarm for completed sales, also create a key under UniFi Site
   Manager → Settings → API Keys and enter it with the ID of a matching Alarm
   Manager webhook trigger. The key is verified against Protect's official local
   integration API before it is saved. Leave alarm fields blank to retain saved
   values when the same console is verified, or use the disable button to remove
   them locally even when the Protect console is unavailable.
   After saving, review the transaction-flag status and use **Send test Protect
   flag** once. The app requires confirmation because this intentionally runs
   every action attached to that Protect alarm.
   Changing the saved host/IP or port—or changing or losing the NVR identity
   reported by a previously bound console—requires the **Confirm console switch**
   checkbox. Each confirmation is short-lived and bound to the verified target.
   Because aliases cannot reliably prove identity, every host-string change is
   treated as a different console: camera mappings, camera associations,
   thumbnails, and thumbnail retries are cleared while Square transaction facts
   remain unassociated. Re-select the POS cameras afterward; the new mappings
   apply to new sales, not retained history.
   Upgraded installations that predate console identities bind the first identity
   seen on a successful reconnect; every later mismatch requires a confirmed reset.
   If a Protect version never reports an NVR id or MAC, the saved host string is
   the only available identity boundary.
3. **Settings → Square account** — a Square access token
   (Developer Dashboard → your application → Credentials). Optionally add your
   webhook signature key and notification URL for real-time ingestion
   (subscribe the webhook to both `payment.created` and `payment.updated`, pointing at
   `https://<your-host>:3546/webhooks/square`). Existing installations must reconnect
   Square once after upgrading so webhook events can be bound to that merchant.
   Changing the merchant or switching between Sandbox and Production requires
   confirmation and clears the previous account's local transactions, camera
   mappings, sync history, and webhook configuration. Re-map the production
   cameras and configure its webhook afterward. If old thumbnail files cannot
   be removed immediately, the account switch still completes and cleanup
   retries automatically, including after a restart.
4. **Settings → POS camera** — pick the camera that watches each location's
   register.
5. **Settings → Thumbnail storage** — optionally enable JPEG compression and
   choose an age or total-size limit. Use *Optimize existing thumbnails now*
   once to apply the active compression policy to already-captured files.
6. Optional: enable **Settings → Motion without a transaction** for the POS
   camera. Copy the generated URL and one-time-displayed token into a Protect
   Alarm Manager Custom Webhook action as documented below.
7. Open **Transactions** — press *Sync now* for an immediate backfill; the
   poller (`SPI_POLL_INTERVAL`, default 60 s) keeps it current thereafter.
8. Optional: use **Settings → App users** to add view-only staff accounts or
   another administrator. Password resets immediately revoke that user's
   existing sessions; resetting your own password returns you to login.
   The **Login history** below the account list shows successful sign-ins and
   can load the complete append-only history in bounded pages.
9. Administrators can enter a **Clip note** directly on any transaction card.
   Saved note text becomes searchable immediately; concurrent stale edits are
   rejected instead of silently overwriting another administrator's work.

## Configuration

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `SPI_DATA_DIR` | `./data` | SQLite DB, encryption key/HMAC salt, thumbnails |
| `SPI_HOST` | `127.0.0.1` | Server bind address. Wildcard and non-loopback values require TLS plus a bootstrap secret for first setup. |
| `SPI_PORT` | `3546` | Fixed Square Protect port used by every packaged launcher; override only when the deployment and webhook URLs are updated together. |
| `SPI_BOOTSTRAP_SECRET` | generated at startup | Random 32–4096 character one-time secret required when creating the first admin password; generate with `openssl rand -base64 32`. Missing or invalid values are replaced with an ephemeral secret printed once to the server console. Only its digest remains in memory, and it is never written to the data directory. |
| `SPI_POLL_INTERVAL` | `60` | Seconds between Square polls |
| `SPI_DISABLE_POLLER` | `0` | Set `1` to disable background polling |
| `SPI_COOKIE_SECURE` | `0` | Set `1` when serving over HTTPS |
| `SPI_ENCRYPTION_KEY` | — | Fernet key overriding the on-disk key file |
| `SPI_TLS` | `0` | Set `1` to serve HTTPS with an auto-generated self-signed certificate; enables Secure cookies automatically. |
| `SPI_TLS_CERTFILE` | — | Absolute path to an administrator-managed PEM certificate or certificate chain. Requires `SPI_TLS=1` and `SPI_TLS_KEYFILE`. |
| `SPI_TLS_KEYFILE` | — | Absolute path to the matching unencrypted PEM private key. The key must not be accessible to group or other users. |

Every first-time setup requires the one-time secret. The configured bind host,
socket peer, HTTP `Host`, optional `Origin`, and absence of forwarding headers
must all indicate loopback before HTTP is allowed. All other requests require
the app's built-in TLS (`SPI_TLS=1`); request URL schemes and
`X-Forwarded-Proto` never satisfy that rule. This keeps DNS rebinding and
reverse/local proxies from removing the secret or transport requirements.
Login throttling uses the directly observed socket address, while bootstrap
authorization remains independent and fail-closed.

Square Protect reserves TCP port `3546` so it can coexist with Farm Dashboard's
controller on port `8000`. Packaged launchers stop with an error when the
configured port is occupied instead of silently selecting another port; stable
ports keep Square and UniFi Protect webhook URLs valid after restarts. Existing
installations upgrading from port `8000` must update LAN firewall rules,
bookmarks, and inbound Square or Protect webhook URLs to use port `3546`.

To replace the generated self-signed certificate with a certificate trusted by
your LAN devices, set `SPI_TLS_CERTFILE` and `SPI_TLS_KEYFILE` to absolute paths
and restart the service. The runner validates the certificate dates, matching
private key, and private-key permissions before it opens a socket. Certificate
renewal remains administrator-managed; restart the service after replacing the
files so the Rust TLS server loads the renewed pair. If either path is missing or invalid,
startup fails instead of silently falling back to another certificate.

Apple Developer ID signing and notarization secure distribution of the macOS
app but cannot authenticate this HTTPS listener to Protect. Do not embed the
Developer ID key or a shared TLS key in the dmg. See
[Protect event delivery and TLS trust](TLS.md) for the unconfirmed webhook
diagnosis, the recommended local event-stream design, and webhook fallbacks.

The app removes the plaintext bootstrap secret from its own process environment
immediately after hashing it. The launching shell, service manager, or container
configuration can still retain the original value. After setup succeeds, unset
`SPI_BOOTSTRAP_SECRET` there and restart the app. To rotate a configured secret
before setup, stop the app, replace the environment value, and restart. An
automatically generated secret rotates on every pre-setup restart, so only the
newly printed value remains valid. Changing this secret after setup does not
rotate the admin password.

The Protect timeline URL can be adjusted under **Settings → Protect timeline
link**. Custom templates must use `https://` with `{host}` as the entire hostname and include
`{camera_id}` and `{ts_ms}`; leave the field blank to restore the built-in
default (verified on Protect 7.1.87):
`https://{host}/protect/timelapse/{camera_id}?start={ts_ms}`.

### Motion without a transaction

Use [Protect's native Motion Zones](https://help.ui.com/hc/en-us/articles/360056987954-UniFi-Protect-Manage-Camera-Zones)
for the user-drawn box instead of decoding the camera stream in this app. The
camera/NVR detection pipeline remains active when this companion app restarts,
is tuned by the camera firmware, and avoids a second continuous video decoder.
In Protect, open the chosen camera's **Recording Mode → Detection & Privacy
Zones** and draw the register zone. Then create an **Activity → Motion** alarm
scoped only to that camera and add a [Custom Webhook](https://help.ui.com/hc/en-us/articles/25478744592023-Send-UniFi-Protect-Alerts-to-Web-Services-using-Webhooks)
action.

The most compatible secure setup uses the documented HTTP GET action:

1. Copy the webhook URL shown by the app. It is built from the browser's current
   origin, so it follows a changed LAN address or hostname.
2. Add the displayed `X-SPI-Webhook-Token` custom header and copy its value when
   the app creates it. The value is shown only on creation, rotation, or a
   camera change; changing cameras invalidates the old alarm action.
3. Enable Protect's **Ignore Repeated Actions** option and test by walking
   through the zone.

GET records the app server's LAN receipt time. The endpoint also accepts the
documented Alarm Manager POST JSON and uses its NVR `timestamp`; prefer POST
when the installed Protect version preserves the custom authentication header
for POST actions. The Protect console must trust the app's HTTPS certificate.

Each event captures its camera, match window, grace period, and expiry at
receipt. A transaction on another camera never resolves it. After the grace
period, an unmatched event is flagged; a late Square webhook or overlap poll
automatically changes it to matched. Exact POST retries and GET deliveries in
the same five-second bucket are deduplicated. Raw Alarm Manager payloads are
not retained, expired rows are pruned, and a 50,000-row hard cap prevents
unbounded database growth. A confirmed Protect console switch disables the
receiver and clears old-console events. A confirmed Square merchant switch
clears old matching results but keeps the current Protect detector enabled.

Thumbnail compression and retention are disabled by default on upgrade. Under
**Settings → Thumbnail storage**, compression affects new captures immediately;
the explicit optimization button processes older files once per compression
policy revision. A retention age of `0` keeps files forever and a storage limit
of `0` is unlimited. Background Square polling, manual sync, settings changes,
and application startup all schedule maintenance.
The oldest JPEGs are retired first until both limits are satisfied. Retired
transactions remain searchable and keep their Protect timeline links, and are
marked so later Square overlap polls cannot recreate the deleted bytes.

> **Note on historical thumbnails:** verified against a UNVR G2 running
> Protect 7.1.87 — historical frames come from the `recording-snapshot`
> endpoint (the live `snapshot` endpoint silently ignores `ts` on this
> firmware). Recorded frames become available roughly ten seconds behind
> live; a sale ingested in real time gets its thumbnail on the first retry
> pass rather than a wrong-time live frame. On older firmware without
> `recording-snapshot`, historical thumbnails remain pending: the integration
> deliberately refuses the legacy `snapshot?ts` fallback because some Protect
> versions silently return a live frame. Live camera previews remain available.

> **Alarm delivery semantics:** each completed transaction is atomically claimed
> and marked delivered after Protect accepts the trigger. Failed requests are
> released for retry by a later poll or duplicate webhook. On startup and retry
> scans, expired in-progress claims are also released. If a request times out or the
> process crashes after Protect accepts a trigger but before delivery state is
> saved, that sale can trigger the alarm again; the Protect endpoint does not
> provide an idempotency key. Completed sales already stored when alarms are first
> enabled, plus sales imported later whose transaction time predates activation,
> are marked handled rather than replayed as a historical burst. Automatic retry
> uses the Square poller; when `SPI_DISABLE_POLLER=1`, pending deliveries require
> a duplicate webhook or manual **Sync now**.

Protect documents this as
[`POST /v1/alarm-manager/webhook/{id}`](https://developer.ui.com/protect/v7.1.87/post-v1alarm-managerwebhookid):
the path ID is a user-defined string that triggers only alarms configured with
the same ID, and a successful accept returns HTTP 204. In Protect Alarm Manager,
create that incoming webhook trigger and attach the notification or automation
you want to use as the footage flag. The Settings status, dashboard tile, and
transaction cards distinguish actual Protect accepts from historical
transactions suppressed when the feature was enabled. The measured per-card
offset is the Protect response time minus Square's transaction timestamp; it
therefore includes Square delivery and local processing latency. The official
trigger accepts an ID but no event body or historical timestamp, so Protect
marks the receipt time: Square webhooks provide the lowest lag, while the
polling fallback can place the flag up to one poll interval later.

## Security

- **Secrets encrypted at rest** — the Square access token, webhook signature
  key, Protect password, Protect API key, and inbound motion token are
  Fernet-encrypted in SQLite; the key file is created `0600`.
- **Account passwords** are hashed with scrypt; login is throttled after
  repeated failures; sessions are random 256-bit tokens in
  `HttpOnly`/`SameSite` cookies and resolve the account's live role on every
  request. Provider configuration, discovery, health checks, OAuth, camera
  mappings, and manual sync are enforced as administrator-only by the server.
- **Password-reset race protection** — each account has an authentication
  revision. A reset increments it and deletes all of the account's sessions in
  one transaction, so a concurrent login that verified the old password cannot
  publish a session after the reset.
- **Atomic login auditing** — a successful session and its audit row commit in
  the same SQLite transaction. Audit rows snapshot the username and role and
  application-level triggers reject updates or deletes; only administrators can
  read the paginated history.
- **Note edit fencing** — notes are limited to 2,000 characters and use an
  optimistic revision. Changing a note invalidates filtered paging snapshots,
  preventing a continuing search page from silently repeating or skipping rows.
- **Webhooks verified** — Square's `x-square-hmacsha256-signature` is checked
  with a constant-time comparison; unsigned or forged deliveries are rejected,
  the endpoint accepts only payment-created/payment-updated envelopes, and it is
  disabled until a signature key is configured. Duplicate detection retains at
  most 4,096 SHA-256 receipt keys; raw event IDs and payloads are not retained.
  Protect motion deliveries require the rotating secret header and a direct
  RFC 1918, loopback, IPv6 ULA, or link-local socket peer; forwarding headers
  are ignored.
- **Request bodies bounded** — general HTTP requests are capped at 1 MiB before
  routing, authentication, or JSON parsing, including streamed/chunked bodies;
  this leaves ample room for the maximum 500-entry camera mapping. Square
  webhooks retain their dedicated 1 MiB streaming/HMAC cap, transaction search
  uses a tighter auth-first streaming cap, and an authenticated Protect motion
  POST is limited to 32 KiB.
- **Input validation** — Protect host and camera ids are strictly validated
  (no URL/path injection), thumbnail serving is confined to the thumbnail
  directory, and the frontend renders all server data as text, never markup.
- **Protect TLS** — certificate verification is off by default for local
  self-signed consoles. Install/trust the console certificate and enable
  **Verify TLS certificate** whenever possible; otherwise local credentials
  and the Protect API key rely on the LAN being trusted.

Serve the integration over HTTPS (reverse proxy) and set `SPI_COOKIE_SECURE=1`
in production. Only the Square webhook route needs internet reachability. The
Protect motion webhook is intentionally LAN-only; everything else can remain
behind the authenticated interface.

## FAQ

**Do I need the Square "Application ID" (or "Sandbox Application ID")?**
Only if you use the "Connect with Square" (OAuth) sign-in, where it serves as
the OAuth client id. If you paste an access token manually instead, the
Application ID is not needed: it identifies your *application* in OAuth
authorization flows and in Square's client-side SDKs (such as the Web Payments
SDK that renders card forms in a browser), while this integration's
server-side Payments/Locations/Webhook API calls authenticate with the
**access token** alone. For manual setup, copy the access token from the same
Credentials page and ignore the Application ID.

**Sandbox or Production?** Use the Sandbox token (and select *Sandbox* in
Settings) to trial the integration with fake payments you create from the
Square developer dashboard; switch to the Production token for real sales.
The two are separate environments with separate tokens.

## Development

Read [SECURITY.md](SECURITY.md) before contributing. Never use deployment
credentials, private keys, merchant data, camera names, or real site addresses
in code, tests, documentation, commits, issues, or pull requests. Run the
repository secret check before every commit:

```bash
./scripts/check-secrets.sh
```

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
cargo test --locked --features menubar --bin square-protect-menubar
```

Install Node.js as well as Rust when running the full suite; the test cases and
assertions are Rust, while browser-helper behavior executes in Node so the
shipped JavaScript—not a reimplementation—is tested. Provider, persistence,
security, packaging, browser-contract, TLS, and concurrency tests run locally
without real Square or UniFi credentials. Passing tests do not validate
firmware-specific snapshot or timeline behavior on real hardware.

The opt-in live-provider suite creates exactly ten completed Square Sandbox
payments and verifies both motion-correlation outcomes using a camera selected
at runtime. The Protect tests confirm that the configured credentials can list
that camera, then inject a webhook directly into the in-process application.
They do not test outbound delivery from the Protect console, DNS, routing, TLS,
firewall rules, or the header configured in Protect. Run the suite
interactively so missing values are requested without echoing passwords or
writing them to disk:

```bash
scripts/run-live-provider-tests.sh
```

The live tests are ignored by the normal `cargo test` commands. They accept
`SPI_TEST_SQUARE_ACCESS_TOKEN`, `SPI_TEST_PROTECT_HOST`,
`SPI_TEST_PROTECT_USERNAME`, `SPI_TEST_PROTECT_PASSWORD`, and
`SPI_TEST_PROTECT_CAMERA_NAME` from the process environment when a
non-interactive secret runner already provides them. Never put those values in
a tracked file.

## License

MIT — see [LICENSE](LICENSE).
