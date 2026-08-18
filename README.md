# Kratos Auth PoC

Docker Compose PoC where **auth-service** (Go) is the only public entrypoint. Ory Kratos v26.2.0 runs on an internal network with no published ports. A static test console exercises register, login, linking, TOTP, step-up, logout, and account deletion.

## Prerequisites

1. **Static ngrok domain** (passkeys, Google OAuth redirect URI, and Telegram BotFather domain all bind to the hostname).
2. **Google Cloud OAuth** web client with authorized redirect URI:
   ```
   https://<your-host>/auth/kratos/self-service/methods/oidc/callback/google
   ```
3. **Telegram OIDC** via BotFather → Login Widget: set Allowed URL to
   ```
   https://<your-host>/auth/kratos/self-service/methods/oidc/callback/telegram
   ```
   Use the **Client ID** and **Client Secret** from BotFather (not the bot token) as
   `TELEGRAM_OIDC_CLIENT_ID` / `TELEGRAM_OIDC_CLIENT_SECRET`.

## Quick start

```bash
cp .env.example .env
# Edit .env: PUBLIC_BASE_URL, PUBLIC_HOST, Google + Telegram credentials

make keys    # generates keys/jwt.pem
make up      # docker compose up --build -d

# In another terminal, expose port 8080:
ngrok http 8080 --domain=<your-subdomain>.ngrok-free.app
```

Open `https://<your-host>/` for the test console.

Email OTP codes are logged by auth-service:

```bash
docker compose logs -f auth-service
```

## Architecture

| Component | Role |
|-----------|------|
| `auth-service:8080` | Public facade API, JWT issuer, session token cookie, static UI |
| `kratos` | Identity server (internal only) |
| `dynamodb-local` | Auth-service user id mapping |
| `postgres` | Kratos database |

Kratos has **no inbound ports** but needs **outbound** access to Google and Telegram for OAuth token exchange.

All Kratos self-service flows use the **native API** (`/self-service/*/api`) with `X-Session-Token` — no browser/CSRF flows. OIDC login/register uses session-token exchange codes; the only browser hop is the OAuth provider redirect (proxied at `/auth/kratos/*`).

## API overview

- `GET /api/v1/session` — current session + JWT
- `POST /api/v1/auth/email-otp/start|verify`
- `POST /api/v1/auth/passkey/register/start|finish`, `login/start|finish`
- `POST /api/v1/auth/oidc/{google|telegram}/start`
- `GET /api/v1/auth/methods`, link/unlink passkey and OIDC
- `POST /api/v1/auth/2fa/totp/start|confirm`, `DELETE /api/v1/auth/2fa/totp`
- `POST /api/v1/auth/stepup/aal2/start|totp`, `stepup/refresh/start`
- `POST /api/v1/auth/logout`, `DELETE /api/v1/auth/account`
- `GET /api/v1/auth/error` — Kratos error redirect target (JSON)
- `GET /api/v1/auth/oidc/return` — OIDC session-token exchange callback

See [docs/poc-plan.md](docs/poc-plan.md) for full design notes.

## Manual test matrix

See [docs/test-matrix.md](docs/test-matrix.md).
