# Manual test matrix

Run with ngrok HTTPS and real Google + Telegram credentials.

## Register

| # | Action | Expected |
|---|--------|----------|
| 1 | Email OTP register | JWT `aal1`, `linked_methods` includes `email_otp`, OTP in logs |
| 2 | Passkey register | Session created, `linked_methods` includes `passkey` |
| 3 | Google register | `linked_methods` includes `google`, traits have `google_email` |
| 4 | Telegram register | `linked_methods` includes `telegram`, traits have `telegram_id` |

## Login

| # | Action | Expected |
|---|--------|----------|
| 5 | Email OTP login | Same `user_id` if same email identity |
| 6 | Passkey login | `methods_used` includes `passkey` |
| 7 | Google login | `methods_used` includes `oidc:google` |
| 8 | Telegram login | `methods_used` includes `oidc:telegram` |

## Link methods (single identity)

| # | Action | Expected |
|---|--------|----------|
| 9 | Google then link passkey | `linked_methods`: `[google, passkey, email_otp]` |
| 10 | Add TOTP | QR shown, after confirm `linked_methods` includes `totp` |
| 11 | Link Telegram | `telegram_id` in session/JWT |

## Step-up

| # | Action | Expected |
|---|--------|----------|
| 12 | Login Google (aal1) then step-up TOTP | `aal2`, `methods_used` includes `totp` |
| 13 | Settings after 1h (or lower privileged max age) | `session_refresh_required`, refresh then retry |

## Remove methods

| # | Action | Expected |
|---|--------|----------|
| 14 | Unlink Google | `google` removed from `linked_methods` |
| 15 | Remove passkey | `passkey` removed |
| 16 | Delete TOTP | `totp` removed, login back to aal1 |
| 17 | Try remove last 1FA | Kratos error / disabled remove button |

## Lifecycle

| # | Action | Expected |
|---|--------|----------|
| 18 | Logout | Session cleared, cookies cleared |
| 19 | Delete account | Identity gone, DynamoDB rows purged |

## Debug pane

Confirm debug endpoints show raw Kratos `whoami` and admin identity with credentials.
