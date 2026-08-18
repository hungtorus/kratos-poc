#!/bin/sh
set -eu

# Kratos does not expand ${VAR} placeholders in mounted YAML — substitute at boot.
CONFIG=/tmp/kratos.yml

: "${PUBLIC_BASE_URL:?PUBLIC_BASE_URL is required}"
: "${PUBLIC_HOST:?PUBLIC_HOST is required}"
: "${GOOGLE_CLIENT_ID:?GOOGLE_CLIENT_ID is required}"
: "${GOOGLE_CLIENT_SECRET:?GOOGLE_CLIENT_SECRET is required}"
: "${TELEGRAM_OIDC_CLIENT_ID:?TELEGRAM_OIDC_CLIENT_ID is required (BotFather Client ID)}"
: "${TELEGRAM_OIDC_CLIENT_SECRET:?TELEGRAM_OIDC_CLIENT_SECRET is required (BotFather Client Secret)}"
: "${COURIER_WEBHOOK_SECRET:=dev-courier-secret}"

sed \
  -e "s|\${PUBLIC_BASE_URL}|${PUBLIC_BASE_URL}|g" \
  -e "s|\${PUBLIC_HOST}|${PUBLIC_HOST}|g" \
  -e "s|\${GOOGLE_CLIENT_ID}|${GOOGLE_CLIENT_ID}|g" \
  -e "s|\${GOOGLE_CLIENT_SECRET}|${GOOGLE_CLIENT_SECRET}|g" \
  -e "s|\${TELEGRAM_OIDC_CLIENT_ID}|${TELEGRAM_OIDC_CLIENT_ID}|g" \
  -e "s|\${TELEGRAM_OIDC_CLIENT_SECRET}|${TELEGRAM_OIDC_CLIENT_SECRET}|g" \
  -e "s|\${COURIER_WEBHOOK_SECRET}|${COURIER_WEBHOOK_SECRET}|g" \
  /etc/config/kratos/kratos.yml > "$CONFIG"

exec kratos serve -c "$CONFIG" --watch-courier
