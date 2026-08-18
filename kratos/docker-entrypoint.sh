#!/bin/sh
set -eu

# Kratos does not expand ${VAR} placeholders in mounted YAML — substitute at boot.
CONFIG=/tmp/kratos.yml

: "${PUBLIC_BASE_URL:?PUBLIC_BASE_URL is required}"
: "${PUBLIC_HOST:?PUBLIC_HOST is required}"
: "${GOOGLE_CLIENT_ID:?GOOGLE_CLIENT_ID is required}"
: "${GOOGLE_CLIENT_SECRET:?GOOGLE_CLIENT_SECRET is required}"
: "${TELEGRAM_BROKER_CLIENT_ID:=kratos}"
: "${TELEGRAM_BROKER_CLIENT_SECRET:?TELEGRAM_BROKER_CLIENT_SECRET is required}"
: "${TELEGRAM_BROKER_ISSUER:=http://auth-service:8080/internal/oidc/telegram}"
: "${COURIER_WEBHOOK_SECRET:=dev-courier-secret}"

sed \
  -e "s|\${PUBLIC_BASE_URL}|${PUBLIC_BASE_URL}|g" \
  -e "s|\${PUBLIC_HOST}|${PUBLIC_HOST}|g" \
  -e "s|\${GOOGLE_CLIENT_ID}|${GOOGLE_CLIENT_ID}|g" \
  -e "s|\${GOOGLE_CLIENT_SECRET}|${GOOGLE_CLIENT_SECRET}|g" \
  -e "s|\${TELEGRAM_BROKER_CLIENT_ID}|${TELEGRAM_BROKER_CLIENT_ID}|g" \
  -e "s|\${TELEGRAM_BROKER_CLIENT_SECRET}|${TELEGRAM_BROKER_CLIENT_SECRET}|g" \
  -e "s|\${TELEGRAM_BROKER_ISSUER}|${TELEGRAM_BROKER_ISSUER}|g" \
  -e "s|\${COURIER_WEBHOOK_SECRET}|${COURIER_WEBHOOK_SECRET}|g" \
  /etc/config/kratos/kratos.yml > "$CONFIG"

exec kratos serve -c "$CONFIG" --watch-courier
