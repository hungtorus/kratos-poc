# Kratos + Go Auth Service PoC — Implementation Plan

Target: a `docker compose` PoC where a Go auth service is the **only** publicly reachable
component, Ory Kratos (v26.2.0) stays on an internal network, and a static test console
exercises every auth action. No unit tests, no refactoring passes — optimise for
"works end to end and is easy to debug".

Reference for conventions: `consensys-vertical-apps/va-mmcx-authentication-api`
(Fiber router, `cleanenv` config, DynamoDB profile store keyed by hashed identifier,
`amr`/`idp_sub` JWT claims, `apihttp` error type). Deliberate deviations for the PoC:
no Ory Hydra and no AWS KMS — the auth service signs its own RS256 JWT with a local key
and publishes JWKS.

---

## 1. Decisions already made

- **Full facade**: browser talks to the Go service only. It never sees Kratos JSON.
- **Real IdPs**: real Google OAuth client, real Telegram bot ⇒ a public HTTPS base URL
  (ngrok) is required. Everything is driven off a single `PUBLIC_BASE_URL` env var.
- **KV store**: DynamoDB Local, table design mirroring the real service.

## 2. Hard constraints discovered during research (these drive the design)

Verified against Kratos `v26.2.0` source:

1. **OIDC login/register uses native API + session-token exchange.** Start
   `GET /self-service/{login,registration}/api?return_session_token_exchange_code=true&return_to=…`,
   submit `{"method":"oidc","provider":"…"}`, complete OAuth at the provider, then exchange
   `init_code` + `return_to_code` at `/sessions/token-exchange` for an `X-Session-Token`.
   The auth-service stores the init code in `poc_oidc_ctx` and handles exchange at
   `GET /api/v1/auth/oidc/return`.
2. **OIDC link in settings** still requires a browser callback hop (Kratos continuity cookie).
   The auth-service injects `X-Session-Token` on proxied `/auth/kratos/*` callbacks so the
   existing session is preserved. Unlink works fully via native settings API.
3. **Telegram uses official OIDC** at `https://oauth.telegram.org` (generic provider) — no shim.
4. **`session.whoami.required_aal` and `selfservice.flows.settings.required_aal` default to
   `highest_available`**: once TOTP is enrolled, aal1 sessions get `403 session_aal2_required`
   from `whoami` and from settings. Set both to `aal1` so the PoC can *show* aal1 vs aal2 and
   drive step-up explicitly.
5. **Registration style defaults to `profile_first` (two-step)** in v26.2.0. Set
   `selfservice.flows.registration.style: unified` so one flow render contains all credential nodes.
6. **The `code` credential is auto-created from the identity schema annotation** — every
   identity with an `email` trait (even a Google-only one) has `credentials.code`. So "linked
   methods" must be derived from credential *configs*, not from the presence of a credential row.
7. **Privileged session**: `selfservice.flows.settings.privileged_session_max_age` (default 1h)
   gates passkey add/remove, TOTP enroll/unlink and OIDC link. When stale, the settings submit
   returns `403 session_refresh_required`; satisfy it with
   `GET /self-service/login/api?refresh=true` + any first factor.
8. **Error UI**: set `selfservice.flows.error.ui_url` to `${PUBLIC_BASE_URL}/api/v1/auth/error`
   so OAuth failures return JSON instead of Kratos' default error page.
9. Courier over HTTP: template types use underscores (`login_code_valid`,
    `registration_code_valid`); the OTP lives at `ctx.template_data.login_code` /
    `ctx.template_data.registration_code`. `courier.smtp.connection_uri` is **not** required
    when `delivery_strategy: http`.
11. Passkey settings nodes: `passkey_create_data` + `passkey_settings_register` (add),
    `passkey_remove` (remove, value = hex credential id, `disabled: true` when it is the last
    first factor). Login nodes: `passkey_challenge` + `passkey_login`. Registration:
    `passkey_create_data` + `passkey_register`.
12. Passkey requires exactly one schema trait annotated `passkey.display_name` with a
    **unique non-empty `title`**, otherwise registration options fail to hydrate.
13. `update_identity_on_login` does **not** exist in OSS v26.2.0 and will fail config
    validation. OIDC mappers run at registration only — traits are not refreshed on later logins.

## 3. Architecture

```mermaid
flowchart LR
  subgraph public [Public - ngrok HTTPS]
    Browser[Test console SPA]
    Google[accounts.google.com]
    TG[Telegram Login Widget]
  end

  subgraph edge [auth-service :8080 - only published port]
    Facade["Facade API /api/v1/auth/*"]
    Proxy["Proxy /auth/kratos/* and /auth/idp/telegram/*"]
    Static[Static console + JWKS]
  end

  subgraph backend [internal docker network - no published ports]
    Kratos[Ory Kratos]
    PG[(Postgres)]
    Shim[telegram-oidc shim]
    Dynamo[(DynamoDB Local)]
  end

  Browser --> Facade
  Browser --> Static
  Browser -->|redirect hops| Proxy
  Browser --> Google
  Browser --> TG
  Facade -->|"public API + cookie relay"| Kratos
  Facade -->|admin API| Kratos
  Facade --> Dynamo
  Proxy --> Kratos
  Proxy --> Shim
  Kratos --> PG
  Kratos -->|"discovery, token, jwks"| Shim
  Kratos -->|courier HTTP| Facade
  Kratos -->|OAuth token exchange| Google
```

Google login sequence (login, register and link are the same shape — only the flow kind differs):

```mermaid
sequenceDiagram
  participant B as Browser
  participant A as auth-service
  participant K as Kratos
  participant G as Google
  B->>A: POST /api/v1/auth/oidc/google/start {intent}
  A->>K: GET /self-service/login/browser (Accept json, relay cookies)
  K-->>A: flow + csrf_token + Set-Cookie
  A->>K: POST /self-service/login?flow=..&{method:oidc,provider:google,csrf_token}
  K-->>A: 422 browser_location_change_required + redirect_browser_to
  A-->>B: {redirect_url} + Set-Cookie relayed
  B->>G: navigate
  G-->>B: 302 to PUBLIC/auth/kratos/self-service/methods/oidc/callback/google
  B->>A: callback (cookies attached)
  A->>K: proxied, prefix stripped
  K-->>B: 303 to PUBLIC/#callback + ory_kratos_session
  B->>A: GET /api/v1/session
  A->>K: GET /sessions/whoami + GET /admin/identities/{id}?include_credential=...
  A-->>B: {user_id, aal, methods_used, linked_methods, jwt}
```

## 4. Repo layout

```
docker-compose.yml
.env.example
Makefile
README.md
docs/poc-plan.md              # this file
docs/test-matrix.md           # manual test checklist
kratos/
  kratos.yml
  identity.schema.json
  oidc.google.jsonnet
  oidc.telegram.jsonnet
  courier.jsonnet
auth-service/
  Dockerfile
  go.mod
  cmd/server/main.go
  internal/config/config.go          # cleanenv + godotenv
  internal/httpapi/                  # fiber routes, handlers, middleware, errors
  internal/kratosx/                  # flow relay client + admin client + method aggregation
  internal/store/                    # dynamo tables + auto-create on boot
  internal/token/                    # RS256 signer, JWKS handler, jti revocation
  web/                               # static console (index.html, app.js, style.css)
telegram-oidc/
  Dockerfile
  go.mod
  main.go                            # discovery, /authorize, /telegram/callback, /oauth2/token, /jwks
```

## 5. docker compose

Services (only `auth-service` publishes a port):

- `postgres` (kratos DSN) — no `ports:`
- `kratos-migrate` (`oryd/kratos:v26.2.0`, `migrate sql -e --yes`)
- `kratos` (`oryd/kratos:v26.2.0 serve -c /etc/config/kratos/kratos.yml --watch-courier`) — no `ports:`
- `telegram-oidc` — no `ports:`
- `dynamodb-local` (`amazon/dynamodb-local`) — no `ports:` (optionally publish for debugging)
- `auth-service` — `ports: ["8080:8080"]`
- optional `ngrok` (`ngrok/ngrok:latest`, `http auth-service:8080 --domain=$NGROK_DOMAIN`) so the
  tunnel is part of compose; otherwise run `ngrok http 8080` on the host.

Networks: single `backend` bridge network. Kratos must keep **outbound** access (Google discovery +
token exchange), so it cannot be `internal: true`; "internal only" is enforced by publishing no
ports and by there being no ingress path except through `auth-service`. Note this in the README.

Key env (`.env.example`):

```
PUBLIC_BASE_URL=https://<reserved>.ngrok-free.app
PUBLIC_HOST=<reserved>.ngrok-free.app          # = passkey rp.id, cookie domain, BotFather domain
GOOGLE_CLIENT_ID=... 
GOOGLE_CLIENT_SECRET=...
TELEGRAM_BOT_TOKEN=...
TELEGRAM_BOT_USERNAME=...
TELEGRAM_OIDC_CLIENT_ID=kratos-poc
TELEGRAM_OIDC_CLIENT_SECRET=kratos-poc-secret
KRATOS_PUBLIC_URL=http://kratos:4433
KRATOS_ADMIN_URL=http://kratos:4434
COURIER_WEBHOOK_SECRET=dev-courier-secret
JWT_ISSUER=${PUBLIC_BASE_URL}
JWT_AUDIENCE=kratos-poc-web
JWT_TTL=1h
JWT_PRIVATE_KEY_PATH=/etc/auth/keys/jwt.pem     # generated by `make keys` if absent
PROFILE_IDENTIFIER_SALT=dev-salt
DYNAMODB_ENDPOINT=http://dynamodb-local:8000
DYNAMODB_REGION=us-east-1
```

Manual prerequisites (README): reserve a **static** ngrok domain (rotating hostnames invalidate
passkeys, break BotFather's domain and Google's redirect URI); add
`${PUBLIC_BASE_URL}/auth/kratos/self-service/methods/oidc/callback/google` as an authorized
redirect URI in Google Cloud Console; run BotFather `/setdomain` → `${PUBLIC_HOST}`.

## 6. Kratos configuration (`kratos/kratos.yml`)

Essentials only — full file to be written during implementation:

```yaml
dsn: postgres://kratos:secret@postgres:5432/kratos?sslmode=disable

serve:
  public:
    base_url: ${PUBLIC_BASE_URL}/auth/kratos/   # Kratos still SERVES absolute paths
    cors: { enabled: false }
  admin:
    base_url: http://kratos:4434/

cookies: { domain: ${PUBLIC_HOST}, path: /, same_site: Lax, secure: true }
session:
  cookie: { domain: ${PUBLIC_HOST}, path: /, same_site: Lax, secure: true }
  whoami: { required_aal: aal1 }

selfservice:
  default_browser_return_url: ${PUBLIC_BASE_URL}/
  allowed_return_urls: [ ${PUBLIC_BASE_URL}/ ]
  flows:
    registration: { style: unified, enabled: true }
    login: { style: unified }
    settings: { required_aal: aal1, privileged_session_max_age: 1h }
    logout: { after: { default_browser_return_url: ${PUBLIC_BASE_URL}/ } }
  methods:
    code:
      enabled: true
      passwordless_enabled: true        # mutually exclusive with mfa_enabled
      config: { lifespan: 15m }
    passkey:
      enabled: true
      config:
        rp: { id: ${PUBLIC_HOST}, display_name: "Kratos PoC", origins: [ ${PUBLIC_BASE_URL} ] }
    totp:
      enabled: true
      config: { issuer: "Kratos PoC" }
    oidc:
      enabled: true
      config:
        providers:
          - id: google
            provider: google
            client_id: ${GOOGLE_CLIENT_ID}
            client_secret: ${GOOGLE_CLIENT_SECRET}
            scope: [email, profile]
            mapper_url: file:///etc/config/kratos/oidc.google.jsonnet
          - id: telegram
            provider: generic
            client_id: ${TELEGRAM_OIDC_CLIENT_ID}
            client_secret: ${TELEGRAM_OIDC_CLIENT_SECRET}
            issuer_url: http://telegram-oidc:4457     # NO trailing slash
            scope: [openid]
            claims_source: id_token
            pkce: auto                                # shim omits code_challenge_methods_supported
            mapper_url: file:///etc/config/kratos/oidc.telegram.jsonnet

courier:
  delivery_strategy: http
  http:
    request_config:
      url: http://auth-service:8080/internal/courier
      method: POST
      body: file:///etc/config/kratos/courier.jsonnet
      headers: { Content-Type: application/json }
      auth:
        type: api_key
        config: { name: Authorization, value: "Bearer ${COURIER_WEBHOOK_SECRET}", in: header }

log: { level: debug, format: text }
secrets: { default: [dev-secret-please-change], cookie: [dev-cookie-secret], cipher: [32-char-cipher-secret-000000000] }
```

`kratos/identity.schema.json` — single `user` schema:

- `traits.email` (format email, `title: "E-Mail"` — unique title, required):
  `credentials: { code: {identifier: true, via: email}, passkey: {display_name: true}, totp: {account_name: true} }`,
  `verification.via: email`, `recovery.via: email`.
- `traits.google_email`, `traits.telegram_id` (string), `traits.telegram_username` — plain traits.
- No `password.identifier` annotation (password method is not enabled).

`kratos/oidc.google.jsonnet` — map `claims.email` (only when `claims.email_verified`) into
`traits.email` and `traits.google_email`; subject stays as the credential identifier `google:<sub>`.

`kratos/oidc.telegram.jsonnet` — custom claims are only reachable via `claims.raw_claims.*`:
map `std.toString(raw.telegram_id)` → `traits.telegram_id`, `raw.telegram_username` →
`traits.telegram_username`, and synthesise `traits.email` as
`telegram-<id>@telegram.local` (email is a required trait and Telegram gives none).

`kratos/courier.jsonnet` — `function(ctx)` forwarding `template_type`, `recipient`, `subject`,
`body`, and `template_data.{login_code, registration_code, recovery_code, verification_code}`.

## 7. telegram-oidc shim (small standalone Go service)

Minimal OIDC provider, internal-only except the `/authorize` + widget-callback hops which the
auth-service proxies under `/auth/idp/telegram/*`.

- `GET /.well-known/openid-configuration` →
  `issuer: http://telegram-oidc:4457` (byte-identical to Kratos config),
  `authorization_endpoint: ${PUBLIC_BASE_URL}/auth/idp/telegram/authorize`,
  `token_endpoint`/`jwks_uri` internal, `response_types_supported: ["code"]`,
  `id_token_signing_alg_values_supported: ["RS256"]`, **omit `code_challenge_methods_supported`**
  (so `pkce: auto` degrades to no PKCE) and omit `userinfo_endpoint`.
- `GET /authorize?client_id&redirect_uri&state&scope&response_type=code` → validate client and
  redirect_uri, store the request in memory keyed by a request id, render an HTML page hosting the
  Telegram Login Widget (`data-telegram-login=$BOT_USERNAME`,
  `data-auth-url=${PUBLIC_BASE_URL}/auth/idp/telegram/callback?rq=<request_id>`).
- `GET /telegram/callback` → verify the widget payload per Telegram spec:
  `secret = SHA256(bot_token)`, `data_check_string` = sorted `k=v` joined by `\n` excluding `hash`,
  compare `HMAC-SHA256`; reject `auth_date` older than 5 min. Then mint a one-time `code` bound to
  the telegram user and 302 to Kratos' `redirect_uri` with `code` + original `state`.
- `POST /oauth2/token` → `client_secret_basic`/`_post`, authorization_code grant, respond
  `{access_token, token_type, expires_in, id_token}`. id_token is RS256 with `kid`, claims:
  `iss` (= issuer, byte-exact), `sub` = telegram user id, `aud` = client_id, `exp`, `iat`,
  plus custom `telegram_id`, `telegram_username`, `first_name`, `photo_url`. **No `nonce` claim.**
- `GET /.well-known/jwks.json` → RSA public key (key generated on boot or loaded from a mounted PEM).

Result: Telegram becomes a first-class Kratos `oidc` credential (`telegram:<telegram_id>`), so
linking, unlinking and multi-method login work through the standard Kratos machinery.

## 8. auth-service

### 8.1 Kratos native API client (`internal/kratosx`)

All flows use `/self-service/{kind}/api` with `X-Session-Token` (stored in `poc_kratos_session` cookie):

1. `StartFlow(ctx, kind, sessionToken, query)` → `GET /self-service/{kind}/api?…`
2. `SubmitFlow(ctx, kind, flowID, body, sessionToken)` → `POST /self-service/{kind}?flow=…`
   Interprets: `200` (success + `session_token`), `400` (flow continues),
   `422` (→ `redirect_browser_to` for OIDC), `403 session_refresh_required`.
3. `ExchangeSessionToken(initCode, returnToCode)` → `GET /sessions/token-exchange?…`
4. `flow_ref`: handlers never expose Kratos flow ids. A `poc_flows` row maps
   `flow_ref → {kratos_flow_id, kind, email, ttl}`.
5. `poc_oidc_ctx` stores `{ctx_id, init_code, intent}` for OIDC token exchange.
6. Admin: `GET /admin/identities/{id}`, `DELETE /admin/identities/{id}`, `DELETE /admin/sessions/{id}`.

### 8.2 Method aggregation ("all verified login methods")

`linked_methods` is computed from admin credential configs, not credential presence:

```go
for _, p := range creds["oidc"].Config.Providers { add(p.Provider) }   // "google", "telegram"
if len(creds["passkey"].Config.Credentials) > 0 { add("passkey") }
if creds["totp"].Config.TOTPURL != ""           { add("totp") }
if len(creds["code"].Config.Addresses) > 0      { add("email_otp") }
```

`methods_used` comes from `session.authentication_methods[]`
(`{method, aal, completed_at, provider}`), and `aal` from
`session.authenticator_assurance_level`. This yields exactly the requested behaviour:
google-only ⇒ `aal1 / [google]`; + passkey ⇒ `aal1 / [google, passkey]`;
+ totp ⇒ `aal2 / [google, passkey, totp]` after step-up.

### 8.3 DynamoDB tables (auto-created on boot)

- `poc_users` — PK `user_id` (uuid) → `kratos_identity_id`, `email`, `created_at`, `primary_method`
- `poc_identity_index` — PK `kratos_identity_id` → `user_id`
- `poc_identifiers` — PK `identifier_hash` = `sha256(type + ":" + value + salt)` → `user_id`, `type`
  (`EMAIL`, `GOOGLE`, `TELEGRAM`, `PASSKEY`) — mirrors the real service's Profiles table
- `poc_flows` — PK `flow_ref` → flow mapping above, TTL
- `poc_revoked_jti` — PK `jti` → TTL (logout / delete account)

After every successful Kratos authentication the service upserts the user record and the
per-method identifier rows, so a google+passkey user resolves to one stable `user_id`.

### 8.4 JWT

RS256, key from `JWT_PRIVATE_KEY_PATH` (generated by `make keys`), published at
`GET /.well-known/jwks.json`. Claims: `iss`, `sub` = our `user_id`, `aud`, `exp`, `iat`, `jti`,
`kratos_identity_id`, `aal`, `amr` (e.g. `["oidc:google","passkey"]`), `linked_methods`,
`email`, `google_email`, `telegram_id`. Bearer middleware verifies signature + `jti` denylist.

### 8.5 Facade API surface

Session / debug:
- `GET /api/v1/session` → `{authenticated, user_id, email, aal, methods_used, linked_methods, jwt, kratos:{identity_id, session_id}}`
- `GET /api/v1/debug/session` → raw `whoami` JSON; `GET /api/v1/debug/identity` → raw admin identity incl. credentials
- `GET /.well-known/jwks.json`

Email OTP (1FA):
- `POST /api/v1/auth/email-otp/start` `{email, intent: register|login}` → `{flow_ref, state}`
- `POST /api/v1/auth/email-otp/verify` `{flow_ref, code}` → session + JWT

Passkey (1FA):
- `POST /api/v1/auth/passkey/register/start` `{email}` → `{flow_ref, creation_options}`
- `POST /api/v1/auth/passkey/register/finish` `{flow_ref, credential}`
- `POST /api/v1/auth/passkey/login/start` → `{flow_ref, request_options}`
- `POST /api/v1/auth/passkey/login/finish` `{flow_ref, credential}`

Social (Google / Telegram, same handlers):
- `POST /api/v1/auth/oidc/{provider}/start` `{intent: login|register|link}` → `{redirect_url}`
- `GET /api/v1/auth/oidc/return?ctx=…&code=…` → exchanges session token, redirects to `/`
- `GET /api/v1/auth/error` → JSON error handler for Kratos error redirects
- `ANY /auth/kratos/*` → reverse proxy to Kratos (OAuth provider callbacks only; injects `X-Session-Token`)

Linked-method management (session required):
- `GET /api/v1/auth/methods` → `[{type, provider, label, added_at, can_remove}]`
- `POST /api/v1/auth/methods/passkey/start` / `.../finish` (settings flow add)
- `DELETE /api/v1/auth/methods/passkey/{credential_id}` (`passkey_remove`)
- `DELETE /api/v1/auth/methods/oidc/{provider}` (settings `unlink`)
- Linking a *new* provider reuses `POST /api/v1/auth/oidc/{provider}/start` with `intent=link`

2FA:
- `POST /api/v1/auth/2fa/totp/start` → `{flow_ref, secret, qr_data_uri, otpauth_url}`
- `POST /api/v1/auth/2fa/totp/confirm` `{flow_ref, code}`
- `DELETE /api/v1/auth/2fa/totp` (`totp_unlink: true` — JSON boolean)
- "modify 2FA" = delete + re-enrol (document this; Kratos has no rotate operation)

Step-up:
- `POST /api/v1/auth/stepup/aal2/start` → `{flow_ref, available:["totp"]}`;
  `POST /api/v1/auth/stepup/aal2/totp` `{flow_ref, code}` (login flow with `?aal=aal2`)
- `POST /api/v1/auth/stepup/refresh/start` `{method}` → login flow with `?refresh=true`, completed
  by the matching 1FA endpoints; used automatically when a settings call returns
  `session_refresh_required`

Lifecycle:
- `POST /api/v1/auth/logout` → `DELETE /admin/sessions/{id}`, clear `poc_kratos_session` cookie
- `DELETE /api/v1/auth/account` → `DELETE /admin/identities/{id}` + purge `poc_*` rows + clear cookie

Internal:
- `POST /internal/courier` (bearer `COURIER_WEBHOOK_SECRET`) → logs
  `template_type`, `recipient` and the OTP at info level, returns `200`. This is the
  "print the OTP in the backend log" requirement.

### 8.6 Test console (`auth-service/web`, static, no build step)

Single page, served at `/` from the auth-service (same origin ⇒ WebAuthn + cookies just work),
plain JS + `fetch`, panels:

- **Register / Login**: email OTP (email field + code field), passkey, "Sign in with Google",
  Telegram Login Widget button, plus a copy of the last OTP shown from `/internal/courier`
  (also visible in `docker compose logs auth-service`).
- **Linked methods**: table from `GET /api/v1/auth/methods` with "Link Google", "Link Telegram",
  "Add passkey", and per-row "Remove".
- **2FA**: enrol (QR + secret), confirm, delete, re-enrol.
- **Step-up**: "Step up to aal2" and "Re-authenticate (refresh)".
- **Session / danger zone**: logout, delete account.
- **Debug pane** (always visible): current `aal`, `methods_used`, `linked_methods`, decoded JWT
  header/claims, raw `whoami` session JSON, raw admin identity JSON (with credentials), and a
  scrolling log of every request/response the page made.

## 9. Implementation order

1. Scaffold: compose file, `.env.example`, `Makefile` (`up`, `down`, `logs`, `keys`, `ngrok`), README runbook.
2. Kratos assets: `kratos.yml`, identity schema, two jsonnet mappers, courier jsonnet. Boot
   `postgres` + `kratos-migrate` + `kratos` and confirm the config validates.
3. auth-service skeleton: config, Fiber router, error/log middleware, Dynamo store with
   auto-create, RS256 keystore + JWKS, `/internal/courier`, Kratos flow-relay client,
   `/api/v1/session`, static file serving.
4. Email OTP register + login → first end-to-end JWT; verify OTP appears in logs.
5. Passkey register/login (needs ngrok up, since WebAuthn needs the real hostname), then passkey
   add/remove via settings.
6. Google: `oidc/start` + the `/auth/kratos/*` proxy + link/unlink; confirm one identity holds
   email-otp + passkey + google.
7. telegram-oidc shim + `/auth/idp/telegram/*` proxy + wire the generic provider; link/unlink.
8. TOTP enrol/confirm/delete, aal2 step-up, refresh step-up on `session_refresh_required`.
9. Logout, delete account, debug endpoints.
10. Test console UI.
11. `docs/test-matrix.md`: walk the full matrix (register with each method → link the others →
    add TOTP → step-up → remove methods → last-factor rejection → logout → delete).

## 10. Gotcha checklist to keep handy during implementation

- `issuer_url` and the shim's `issuer`/`iss` must match byte-for-byte (no trailing slash).
- Restart Kratos after editing the shim's discovery document (it is cached).
- Kratos serves absolute paths: the `/auth/kratos` proxy **must strip the prefix**.
- Changing `serve.public.base_url` changes the CSRF cookie name and invalidates in-flight flows.
- Google's authorized redirect URI must be the full proxied Kratos callback path.
- ngrok hostname changes invalidate passkeys (rp.id), BotFather's domain and Google's redirect URI.
- Drop the `Set-Cookie: ory_kratos_continuity` only when you know the hop is headless; for OIDC
  link/login hops it must reach the browser.
- `totp_unlink` is a JSON boolean; `passkey_remove` takes the hex credential id.
- The last remaining first-factor credential cannot be removed (Kratos returns
  `UnlinkAllFirstFactorConnectionsError`, and `passkey_remove` arrives `disabled: true`).
- `DELETE /admin/identities/{id}/credentials/{type}` cannot delete `passkey` or `code` — use the
  settings flow for removals.
- OIDC mappers run at registration only; `telegram_username` will go stale by design.
