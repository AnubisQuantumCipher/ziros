#!/usr/bin/env bash
set -euo pipefail

DOMAIN="ziros.dev"
HOSTNAME="api.${DOMAIN}"
GO_HOSTNAME="go.${DOMAIN}"
BILLING_HOSTNAME="billing.${DOMAIN}"
TUNNEL_NAME="ziros-api"
PROOF_SERVER_PORT="6300"
METERING_PORT="6311"
REDIRECT_PORT="6320"
BILLING_PORT="6330"
BINARY="/Users/sicarii/Desktop/ZirOS/dist/aarch64-apple-darwin/zkf"
CONFIG_PATH="$HOME/.cloudflared/config.yml"
CERT_PATH="$HOME/.cloudflared/cert.pem"
PROOF_SERVER_PLIST="$HOME/Library/LaunchAgents/com.ziros.midnight-proof-server.plist"
TUNNEL_LABEL="com.ziros.cloudflared-ziros-api"
TUNNEL_PLIST="$HOME/Library/LaunchAgents/${TUNNEL_LABEL}.plist"
METERING_LABEL="com.ziros.hosted-proof-metering"
METERING_PLIST="$HOME/Library/LaunchAgents/${METERING_LABEL}.plist"
REDIRECT_LABEL="com.ziros.proof-cta-redirects"
REDIRECT_PLIST="$HOME/Library/LaunchAgents/${REDIRECT_LABEL}.plist"
BILLING_LABEL="com.ziros.proof-checkout-fulfillment"
BILLING_PLIST="$HOME/Library/LaunchAgents/${BILLING_LABEL}.plist"
EDGE_WATCHDOG_LABEL="com.ziros.proof-edge-watchdog"
EDGE_WATCHDOG_PLIST="$HOME/Library/LaunchAgents/${EDGE_WATCHDOG_LABEL}.plist"
ACCESS_HELPER="/Users/sicarii/Desktop/ZirOS/setup/ziros-cloudflare-access.sh"
ACCESS_TEAM="zirosdev"

if [[ $# -gt 0 ]]; then
  DOMAIN="$1"
  HOSTNAME="api.${DOMAIN}"
  GO_HOSTNAME="go.${DOMAIN}"
  BILLING_HOSTNAME="billing.${DOMAIN}"
fi

if ! command -v cloudflared >/dev/null 2>&1; then
  echo "ERROR: cloudflared not installed. Run: brew install cloudflared"
  exit 1
fi

if [[ ! -f "$CERT_PATH" ]]; then
  echo "ERROR: missing $CERT_PATH"
  echo "Run 'cloudflared tunnel login' in a browser-capable session, download cert.pem, and place it at $CERT_PATH"
  echo "The login URL can be run from a GUI-capable environment if needed."
  exit 1
fi

if [[ ! -f "$BINARY" ]]; then
  echo "ERROR: binary not found: $BINARY"
  echo "Build with: cd /Users/sicarii/Desktop/ZirOS && bash scripts/build-binary-release.sh"
  exit 1
fi

if [[ ! -f "$PROOF_SERVER_PLIST" ]]; then
  echo "ERROR: missing $PROOF_SERVER_PLIST"
  echo "Install the managed proof-server LaunchAgent before booting the public lane."
  exit 1
fi

if [[ ! -f "$METERING_PLIST" ]]; then
  echo "ERROR: missing $METERING_PLIST"
  echo "Install the managed metering-proxy LaunchAgent before booting the public lane."
  exit 1
fi

if [[ ! -f "$REDIRECT_PLIST" ]]; then
  echo "ERROR: missing $REDIRECT_PLIST"
  echo "Install the managed CTA redirect LaunchAgent before booting the public lane."
  exit 1
fi

if [[ ! -f "$BILLING_PLIST" ]]; then
  echo "ERROR: missing $BILLING_PLIST"
  echo "Install the managed billing/fulfillment LaunchAgent before booting the public lane."
  exit 1
fi

if [[ ! -f "$EDGE_WATCHDOG_PLIST" ]]; then
  echo "WARN: missing $EDGE_WATCHDOG_PLIST"
  echo "Public edge self-heal will stay disabled until the edge watchdog LaunchAgent is installed."
fi

if ! launchctl print "gui/$(id -u)/com.ziros.midnight-proof-server" >/dev/null 2>&1; then
  echo "INFO: bootstrapping proof-server LaunchAgent"
  launchctl bootstrap "gui/$(id -u)" "$PROOF_SERVER_PLIST"
fi

if ! launchctl print "gui/$(id -u)/${METERING_LABEL}" >/dev/null 2>&1; then
  echo "INFO: bootstrapping metering-proxy LaunchAgent"
  launchctl bootstrap "gui/$(id -u)" "$METERING_PLIST"
else
  launchctl kickstart -k "gui/$(id -u)/${METERING_LABEL}"
fi

if ! launchctl print "gui/$(id -u)/${REDIRECT_LABEL}" >/dev/null 2>&1; then
  echo "INFO: bootstrapping CTA redirect LaunchAgent"
  launchctl bootstrap "gui/$(id -u)" "$REDIRECT_PLIST"
else
  launchctl kickstart -k "gui/$(id -u)/${REDIRECT_LABEL}"
fi

if ! launchctl print "gui/$(id -u)/${BILLING_LABEL}" >/dev/null 2>&1; then
  echo "INFO: bootstrapping billing/fulfillment LaunchAgent"
  launchctl bootstrap "gui/$(id -u)" "$BILLING_PLIST"
else
  launchctl kickstart -k "gui/$(id -u)/${BILLING_LABEL}"
fi

if [[ -f "$EDGE_WATCHDOG_PLIST" ]]; then
  if ! launchctl print "gui/$(id -u)/${EDGE_WATCHDOG_LABEL}" >/dev/null 2>&1; then
    echo "INFO: bootstrapping public edge watchdog LaunchAgent"
    launchctl bootstrap "gui/$(id -u)" "$EDGE_WATCHDOG_PLIST"
  else
    launchctl kickstart -k "gui/$(id -u)/${EDGE_WATCHDOG_LABEL}"
  fi
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq required for status parsing. Install with: brew install jq"
  exit 1
fi

if [[ ! -x "$ACCESS_HELPER" ]]; then
  echo "ERROR: missing executable Access helper: $ACCESS_HELPER"
  exit 1
fi

if ! curl -fsS "http://127.0.0.1:${PROOF_SERVER_PORT}/health" >/dev/null; then
  echo "ERROR: local proof server is not healthy on 127.0.0.1:${PROOF_SERVER_PORT}"
  exit 1
fi

LOCAL_METERING_STATUS="000"
for _ in 1 2 3 4 5; do
  LOCAL_METERING_STATUS="$(curl -sS -o /tmp/ziros-metering-local.out -w '%{http_code}' "http://127.0.0.1:${METERING_PORT}/health" || true)"
  if [[ "$LOCAL_METERING_STATUS" == "401" ]]; then
    break
  fi
  sleep 1
done
if [[ "$LOCAL_METERING_STATUS" != "401" ]]; then
  echo "ERROR: local metering proxy did not fail closed on 127.0.0.1:${METERING_PORT} (got ${LOCAL_METERING_STATUS})"
  exit 1
fi

if ! curl -fsS "http://127.0.0.1:${REDIRECT_PORT}/health" >/dev/null; then
  echo "ERROR: local CTA redirect service is not healthy on 127.0.0.1:${REDIRECT_PORT}"
  exit 1
fi

if ! curl -fsS "http://127.0.0.1:${BILLING_PORT}/health" >/dev/null; then
  echo "ERROR: local billing service is not healthy on 127.0.0.1:${BILLING_PORT}"
  exit 1
fi

echo "Checking Cloudflare Access preconditions for ${HOSTNAME}"
bash "$ACCESS_HELPER" assert-edge-guard "$HOSTNAME" >/dev/null
ACCESS_AUD="$(bash "$ACCESS_HELPER" bootstrap "$HOSTNAME" | jq -r '.app.aud')"
if [[ -z "${ACCESS_AUD:-}" || "$ACCESS_AUD" == "null" ]]; then
  echo "ERROR: failed to determine Cloudflare Access AUD for ${HOSTNAME}"
  exit 1
fi

# Create tunnel only if absent
if cloudflared tunnel list --output json 2>/dev/null | jq -e --arg NAME "$TUNNEL_NAME" 'map(select(.name==$NAME)) | length > 0' >/dev/null; then
  TUNNEL_ID="$(cloudflared tunnel list --output json 2>/dev/null | jq -r --arg NAME "$TUNNEL_NAME" 'map(select(.name==$NAME))[0].id')"
  echo "INFO: tunnel exists: $TUNNEL_NAME ($TUNNEL_ID)"
else
  echo "INFO: creating tunnel $TUNNEL_NAME"
  TUNNEL_ID="$(cloudflared tunnel create "$TUNNEL_NAME" --output json 2>/dev/null | jq -r '.id')"
fi

if [[ -z "${TUNNEL_ID:-}" ]]; then
  echo "ERROR: failed to determine tunnel id"
  exit 1
fi

mkdir -p "$HOME/.cloudflared"
PREVIOUS_CONFIG="$(mktemp)"
if [[ -f "$CONFIG_PATH" ]]; then
  cp "$CONFIG_PATH" "$PREVIOUS_CONFIG"
else
  : > "$PREVIOUS_CONFIG"
fi

cat > "$CONFIG_PATH" <<EOF2
tunnel: $TUNNEL_ID
credentials-file: ${HOME}/.cloudflared/${TUNNEL_ID}.json
origincert: ${CERT_PATH}

ingress:
  - hostname: $HOSTNAME
    service: http://127.0.0.1:$METERING_PORT
    originRequest:
      noTLSVerify: true
      access:
        required: true
        teamName: ${ACCESS_TEAM}
        audTag:
          - ${ACCESS_AUD}
  - hostname: $GO_HOSTNAME
    service: http://127.0.0.1:$REDIRECT_PORT
    originRequest:
      noTLSVerify: true
  - hostname: $BILLING_HOSTNAME
    service: http://127.0.0.1:$BILLING_PORT
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF2

echo "Wrote: $CONFIG_PATH"

echo "Creating DNS route: $HOSTNAME"
cloudflared tunnel route dns "$TUNNEL_ID" "$HOSTNAME"
echo "Creating DNS route: $GO_HOSTNAME"
cloudflared tunnel route dns "$TUNNEL_ID" "$GO_HOSTNAME"
echo "Creating DNS route: $BILLING_HOSTNAME"
cloudflared tunnel route dns "$TUNNEL_ID" "$BILLING_HOSTNAME"

echo "Reloading tunnel"
if [[ -f "$TUNNEL_PLIST" ]]; then
  if launchctl print "gui/$(id -u)/${TUNNEL_LABEL}" >/dev/null 2>&1; then
    launchctl kickstart -k "gui/$(id -u)/${TUNNEL_LABEL}"
  else
    launchctl bootstrap "gui/$(id -u)" "$TUNNEL_PLIST"
  fi
else
  cloudflared tunnel run --config "$CONFIG_PATH" "$TUNNEL_ID" >/tmp/ziros-cloudflared.log 2>&1 &
  TUNNEL_PID=$!
fi
sleep 2

echo "Public edge check (unauthenticated requests should be blocked by Cloudflare Access):"
UNAUTH_STATUS="$(curl -sS -o /dev/null -w '%{http_code}' "https://$HOSTNAME/health" || true)"
if [[ "$UNAUTH_STATUS" != "401" ]]; then
  echo "ERROR: unauthenticated public edge check returned $UNAUTH_STATUS, expected 401" >&2
  echo "Restoring previous tunnel config" >&2
  cp "$PREVIOUS_CONFIG" "$CONFIG_PATH"
  if [[ -f "$TUNNEL_PLIST" ]]; then
    launchctl kickstart -k "gui/$(id -u)/${TUNNEL_LABEL}"
  elif [[ -n "${TUNNEL_PID:-}" ]]; then
    kill "$TUNNEL_PID" >/dev/null 2>&1 || true
  fi
  exit 1
fi
echo "401"

echo "Public redirect health check:"
REDIRECT_PUBLIC_STATUS="000"
for _ in 1 2 3 4 5 6 7 8 9 10; do
  REDIRECT_IP="$(dig +short "$GO_HOSTNAME" | head -n 1 | tr -d '\r')"
  if [[ -n "${REDIRECT_IP:-}" ]]; then
    REDIRECT_PUBLIC_STATUS="$(curl -sS -o /dev/null -w '%{http_code}' --resolve "${GO_HOSTNAME}:443:${REDIRECT_IP}" "https://$GO_HOSTNAME/health" || true)"
  else
    REDIRECT_PUBLIC_STATUS="$(curl -sS -o /dev/null -w '%{http_code}' "https://$GO_HOSTNAME/health" || true)"
  fi
  if [[ "$REDIRECT_PUBLIC_STATUS" == "200" ]]; then
    break
  fi
  sleep 3
done
if [[ "$REDIRECT_PUBLIC_STATUS" != "200" ]]; then
  echo "ERROR: public redirect health check returned $REDIRECT_PUBLIC_STATUS, expected 200" >&2
  echo "Restoring previous tunnel config" >&2
  cp "$PREVIOUS_CONFIG" "$CONFIG_PATH"
  if [[ -f "$TUNNEL_PLIST" ]]; then
    launchctl kickstart -k "gui/$(id -u)/${TUNNEL_LABEL}"
  elif [[ -n "${TUNNEL_PID:-}" ]]; then
    kill "$TUNNEL_PID" >/dev/null 2>&1 || true
  fi
  exit 1
fi
echo "200"

echo "Public billing health check:"
BILLING_PUBLIC_STATUS="000"
for _ in 1 2 3 4 5 6 7 8 9 10; do
  BILLING_IP="$(dig +short "$BILLING_HOSTNAME" | head -n 1 | tr -d '\r')"
  if [[ -n "${BILLING_IP:-}" ]]; then
    BILLING_PUBLIC_STATUS="$(curl -sS -o /dev/null -w '%{http_code}' --resolve "${BILLING_HOSTNAME}:443:${BILLING_IP}" "https://$BILLING_HOSTNAME/health" || true)"
  else
    BILLING_PUBLIC_STATUS="$(curl -sS -o /dev/null -w '%{http_code}' "https://$BILLING_HOSTNAME/health" || true)"
  fi
  if [[ "$BILLING_PUBLIC_STATUS" == "200" ]]; then
    break
  fi
  sleep 3
done
if [[ "$BILLING_PUBLIC_STATUS" != "200" ]]; then
  echo "ERROR: public billing health check returned $BILLING_PUBLIC_STATUS, expected 200" >&2
  echo "Restoring previous tunnel config" >&2
  cp "$PREVIOUS_CONFIG" "$CONFIG_PATH"
  if [[ -f "$TUNNEL_PLIST" ]]; then
    launchctl kickstart -k "gui/$(id -u)/${TUNNEL_LABEL}"
  elif [[ -n "${TUNNEL_PID:-}" ]]; then
    kill "$TUNNEL_PID" >/dev/null 2>&1 || true
  fi
  exit 1
fi
echo "200"

if security find-generic-password -a bitrove-prod -s cloudflare-access-client-id >/dev/null 2>&1; then
  echo "Authenticated edge check (Bitrove service token should succeed):"
  if ! bash "$ACCESS_HELPER" verify bitrove-prod "$HOSTNAME" >/dev/null; then
    echo "ERROR: authenticated Access verification failed after cutover; restoring previous tunnel config" >&2
    cp "$PREVIOUS_CONFIG" "$CONFIG_PATH"
    if [[ -f "$TUNNEL_PLIST" ]]; then
      launchctl kickstart -k "gui/$(id -u)/${TUNNEL_LABEL}"
    elif [[ -n "${TUNNEL_PID:-}" ]]; then
      kill "$TUNNEL_PID" >/dev/null 2>&1 || true
    fi
    exit 1
  fi
  echo "200"
fi

echo "Done. Proof lane: https://$HOSTNAME  Redirect surface: https://$GO_HOSTNAME  Billing surface: https://$BILLING_HOSTNAME"
