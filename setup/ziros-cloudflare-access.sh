#!/usr/bin/env bash
set -euo pipefail

ACCOUNT_ID="6b5f0218e6c2f165fa14e20bcb243b49"
TEAM_DOMAIN="zirosdev.cloudflareaccess.com"
DEFAULT_HOSTNAME="api.ziros.dev"
DEFAULT_APP_NAME="ziros-api"
DEFAULT_CUSTOMER="bitrove-prod"
DEFAULT_SERVICE_TOKEN_DURATION="8760h"
DEFAULT_SESSION_DURATION="24h"
TOKEN_ACCOUNT="zirosdev-access-editor"
TOKEN_SERVICE="cloudflare-user-api-token"

usage() {
  cat <<'EOF'
Usage:
  ziros-cloudflare-access.sh bootstrap [hostname]
  ziros-cloudflare-access.sh issue [customer] [hostname]
  ziros-cloudflare-access.sh status [customer] [hostname]
  ziros-cloudflare-access.sh verify [customer] [hostname]
  ziros-cloudflare-access.sh assert-edge-guard [hostname]
  ziros-cloudflare-access.sh revoke [customer] [hostname]

Defaults:
  hostname = api.ziros.dev
  customer = bitrove-prod

Keychain requirements:
  account "zirosdev-access-editor" / service "cloudflare-user-api-token"

Customer credentials are stored as:
  account "<customer>" / service "cloudflare-access-service-token-id"
  account "<customer>" / service "cloudflare-access-client-id"
  account "<customer>" / service "cloudflare-access-client-secret"
EOF
}

require_commands() {
  local cmd
  for cmd in curl jq security; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "ERROR: missing required command: $cmd" >&2
      exit 1
    fi
  done
}

api_token() {
  security find-generic-password -a "$TOKEN_ACCOUNT" -s "$TOKEN_SERVICE" -w
}

cf_api() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local token

  token="$(api_token)"

  if [[ "$method" == "GET" ]]; then
    curl -sS "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}${path}" \
      -H "Authorization: Bearer ${token}"
    return
  fi

  curl -sS -X "$method" "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}${path}" \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    ${body:+--data "$body"}
}

app_record() {
  local hostname="$1"
  cf_api GET "/access/apps" | jq -cer --arg hostname "$hostname" '.result[]? | select(.domain == $hostname)' | head -n1 || true
}

require_app() {
  local hostname="$1"
  local app_json

  app_json="$(app_record "$hostname")"
  if [[ -z "$app_json" ]]; then
    echo "ERROR: no Cloudflare Access app found for ${hostname}" >&2
    echo "Run: bash /Users/sicarii/Desktop/ZirOS/setup/ziros-cloudflare-access.sh bootstrap ${hostname}" >&2
    exit 1
  fi

  printf '%s\n' "$app_json"
}

ensure_app() {
  local hostname="$1"
  local app_json payload response

  app_json="$(app_record "$hostname")"
  if [[ -n "$app_json" ]]; then
    printf '%s\n' "$app_json"
    return
  fi

  payload="$(jq -n \
    --arg domain "$hostname" \
    --arg name "$DEFAULT_APP_NAME" \
    --arg session_duration "$DEFAULT_SESSION_DURATION" \
    '{
      domain: $domain,
      type: "self_hosted",
      name: $name,
      app_launcher_visible: false,
      session_duration: $session_duration,
      service_auth_401_redirect: true,
      skip_interstitial: true
    }')"

  response="$(cf_api POST "/access/apps" "$payload")"
  jq -e '.success == true' >/dev/null <<<"$response" || {
    echo "ERROR: failed to create Cloudflare Access app" >&2
    jq '{success, errors, messages}' <<<"$response" >&2
    exit 1
  }

  jq -cer '.result' <<<"$response"
}

customer_secret_exists() {
  local customer="$1"
  local service="$2"
  security find-generic-password -a "$customer" -s "$service" >/dev/null 2>&1
}

customer_secret() {
  local customer="$1"
  local service="$2"
  security find-generic-password -a "$customer" -s "$service" -w
}

maybe_customer_secret() {
  local customer="$1"
  local service="$2"

  if customer_secret_exists "$customer" "$service"; then
    customer_secret "$customer" "$service"
  fi
}

store_customer_secret() {
  local customer="$1"
  local service="$2"
  local value="$3"

  security add-generic-password -U -a "$customer" -s "$service" -w "$value" >/dev/null
}

delete_customer_secret() {
  local customer="$1"
  local service="$2"

  security delete-generic-password -a "$customer" -s "$service" >/dev/null 2>&1 || true
}

policy_name_for_customer() {
  local customer="$1"
  local base="$customer"

  for suffix in -prod -staging -stage -dev; do
    if [[ "$base" == *"$suffix" ]]; then
      base="${base%"$suffix"}"
      break
    fi
  done

  if [[ -z "$base" ]]; then
    base="$customer"
  fi

  printf '%s-service-auth\n' "$base"
}

delete_policy() {
  local app_id="$1"
  local policy_id="$2"
  local response

  response="$(cf_api DELETE "/access/apps/${app_id}/policies/${policy_id}")"
  jq -e '.success == true' >/dev/null <<<"$response" || {
    echo "ERROR: failed to delete Cloudflare Access policy ${policy_id}" >&2
    jq '{success, errors, messages}' <<<"$response" >&2
    exit 1
  }
}

bootstrap() {
  local hostname="${1:-$DEFAULT_HOSTNAME}"
  local app_json

  app_json="$(ensure_app "$hostname")"
  jq -n \
    --arg team_domain "$TEAM_DOMAIN" \
    --arg hostname "$hostname" \
    --argjson app "$app_json" \
    '{
      team_domain: $team_domain,
      hostname: $hostname,
      app: {
        id: $app.id,
        name: $app.name,
        domain: $app.domain,
        aud: $app.aud
      },
      service_auth_401_redirect: $app.service_auth_401_redirect,
      non_identity_policy_count: ([$app.policies[]? | select(.decision == "non_identity")] | length)
    }'
}

issue() {
  local customer="${1:-$DEFAULT_CUSTOMER}"
  local hostname="${2:-$DEFAULT_HOSTNAME}"
  local app_json app_id policy_name existing_policy_ids service_payload response
  local token_id client_id client_secret next_precedence policy_payload policy_response

  if customer_secret_exists "$customer" "cloudflare-access-service-token-id"; then
    echo "ERROR: customer ${customer} already has a stored Cloudflare Access credential" >&2
    echo "Use revoke first if you want to replace it." >&2
    exit 1
  fi

  app_json="$(ensure_app "$hostname")"
  jq -e '.service_auth_401_redirect == true' >/dev/null <<<"$app_json" || {
    echo "ERROR: Access app for ${hostname} exists but service_auth_401_redirect is not enabled" >&2
    exit 1
  }
  app_id="$(jq -r '.id' <<<"$app_json")"
  policy_name="$(policy_name_for_customer "$customer")"

  existing_policy_ids="$(jq -r --arg policy_name "$policy_name" '.policies[]? | select(.name == $policy_name) | .id' <<<"$app_json")"
  while IFS= read -r policy_id; do
    [[ -n "$policy_id" ]] || continue
    delete_policy "$app_id" "$policy_id"
  done <<<"$existing_policy_ids"

  service_payload="$(jq -n \
    --arg name "$customer" \
    --arg duration "$DEFAULT_SERVICE_TOKEN_DURATION" \
    '{name: $name, duration: $duration}')"
  response="$(cf_api POST "/access/service_tokens" "$service_payload")"
  jq -e '.success == true' >/dev/null <<<"$response" || {
    echo "ERROR: failed to create Cloudflare Access service token for ${customer}" >&2
    jq '{success, errors, messages}' <<<"$response" >&2
    exit 1
  }

  token_id="$(jq -r '.result.id' <<<"$response")"
  client_id="$(jq -r '.result.client_id' <<<"$response")"
  client_secret="$(jq -r '.result.client_secret' <<<"$response")"

  store_customer_secret "$customer" "cloudflare-access-service-token-id" "$token_id"
  store_customer_secret "$customer" "cloudflare-access-client-id" "$client_id"
  store_customer_secret "$customer" "cloudflare-access-client-secret" "$client_secret"

  app_json="$(require_app "$hostname")"
  next_precedence="$(( $(jq '[.policies[]?.precedence // 0] | max // 0' <<<"$app_json") + 1 ))"
  policy_payload="$(jq -n \
    --arg name "$policy_name" \
    --arg token_id "$token_id" \
    --arg session_duration "$DEFAULT_SESSION_DURATION" \
    --argjson precedence "$next_precedence" \
    '{
      name: $name,
      decision: "non_identity",
      include: [{service_token: {token_id: $token_id}}],
      precedence: $precedence,
      session_duration: $session_duration
    }')"
  policy_response="$(cf_api POST "/access/apps/${app_id}/policies" "$policy_payload")"
  jq -e '.success == true' >/dev/null <<<"$policy_response" || {
    echo "ERROR: failed to create Cloudflare Access policy for ${customer}" >&2
    jq '{success, errors, messages}' <<<"$policy_response" >&2
    exit 1
  }

  jq -n \
    --arg team_domain "$TEAM_DOMAIN" \
    --arg customer "$customer" \
    --arg hostname "$hostname" \
    --arg app_id "$app_id" \
    --arg policy_name "$policy_name" \
    --arg policy_id "$(jq -r '.result.id' <<<"$policy_response")" \
    --arg token_id "$token_id" \
    '{
      team_domain: $team_domain,
      customer: $customer,
      hostname: $hostname,
      app_id: $app_id,
      service_token_id: $token_id,
      policy: {
        id: $policy_id,
        name: $policy_name
      },
      credential_storage: "macOS Keychain"
    }'
}

status() {
  local customer="${1:-$DEFAULT_CUSTOMER}"
  local hostname="${2:-$DEFAULT_HOSTNAME}"
  local app_json token_id

  app_json="$(require_app "$hostname")"
  token_id="$(maybe_customer_secret "$customer" "cloudflare-access-service-token-id")"

  jq -n \
    --arg team_domain "$TEAM_DOMAIN" \
    --arg customer "$customer" \
    --arg token_id "$token_id" \
    --argjson app "$app_json" \
    '{
      team_domain: $team_domain,
      customer: $customer,
      app: {
        id: $app.id,
        name: $app.name,
        domain: $app.domain,
        aud: $app.aud
      },
      service_auth_401_redirect: $app.service_auth_401_redirect,
      service_token_id: (if $token_id == "" then null else $token_id end),
      policies: [$app.policies[]? | {id, name, decision, precedence, include}]
    }'
}

assert_edge_guard() {
  local hostname="${1:-$DEFAULT_HOSTNAME}"
  local app_json

  app_json="$(require_app "$hostname")"
  jq -e '
    .service_auth_401_redirect == true and
    ([.policies[]? | select(.decision == "non_identity")] | length) > 0
  ' >/dev/null <<<"$app_json" || {
    echo "ERROR: Cloudflare Access edge guard is not ready for ${hostname}" >&2
    jq '{id, name, domain, aud, service_auth_401_redirect, policies}' <<<"$app_json" >&2
    exit 1
  }

  jq -n \
    --argjson app "$app_json" \
    '{
      app: {
        id: $app.id,
        name: $app.name,
        domain: $app.domain,
        aud: $app.aud
      },
      service_auth_401_redirect: $app.service_auth_401_redirect,
      non_identity_policies: [$app.policies[]? | select(.decision == "non_identity") | {id, name, precedence}]
    }'
}

verify() {
  local customer="${1:-$DEFAULT_CUSTOMER}"
  local hostname="${2:-$DEFAULT_HOSTNAME}"
  local client_id client_secret base_url
  local unauth_code health_code ready_code version_code
  local health_body ready_body version_body

  client_id="$(customer_secret "$customer" "cloudflare-access-client-id")"
  client_secret="$(customer_secret "$customer" "cloudflare-access-client-secret")"
  base_url="https://${hostname}"

  unauth_code="$(curl -sS -o /tmp/ziros-access-unauth.out -w '%{http_code}' "${base_url}/health" || true)"
  health_code="$(curl -sS -o /tmp/ziros-access-health.out -w '%{http_code}' "${base_url}/health" \
    -H "CF-Access-Client-Id: ${client_id}" \
    -H "CF-Access-Client-Secret: ${client_secret}")"
  ready_code="$(curl -sS -o /tmp/ziros-access-ready.out -w '%{http_code}' "${base_url}/ready" \
    -H "CF-Access-Client-Id: ${client_id}" \
    -H "CF-Access-Client-Secret: ${client_secret}")"
  version_code="$(curl -sS -o /tmp/ziros-access-version.out -w '%{http_code}' "${base_url}/version" \
    -H "CF-Access-Client-Id: ${client_id}" \
    -H "CF-Access-Client-Secret: ${client_secret}")"

  health_body="$(cat /tmp/ziros-access-health.out)"
  ready_body="$(cat /tmp/ziros-access-ready.out)"
  version_body="$(cat /tmp/ziros-access-version.out)"

  jq -n \
    --arg customer "$customer" \
    --arg hostname "$hostname" \
    --arg unauth_code "$unauth_code" \
    --arg health_code "$health_code" \
    --arg ready_code "$ready_code" \
    --arg version_code "$version_code" \
    --arg health_body "$health_body" \
    --arg ready_body "$ready_body" \
    --arg version_body "$version_body" \
    '{
      customer: $customer,
      hostname: $hostname,
      unauthenticated_health_status: ($unauth_code | tonumber),
      authenticated_health_status: ($health_code | tonumber),
      authenticated_ready_status: ($ready_code | tonumber),
      authenticated_version_status: ($version_code | tonumber),
      authenticated_health_body: $health_body,
      authenticated_ready_body: $ready_body,
      authenticated_version_body: $version_body
    }'

  if [[ "$unauth_code" != "401" || "$health_code" != "200" || "$ready_code" != "200" || "$version_code" != "200" ]]; then
    echo "ERROR: Cloudflare Access verification failed for ${hostname}" >&2
    exit 1
  fi
}

revoke() {
  local customer="${1:-$DEFAULT_CUSTOMER}"
  local hostname="${2:-$DEFAULT_HOSTNAME}"
  local app_json app_id token_id policy_ids response

  token_id="$(customer_secret "$customer" "cloudflare-access-service-token-id")"
  app_json="$(require_app "$hostname")"
  app_id="$(jq -r '.id' <<<"$app_json")"

  policy_ids="$(jq -r --arg token_id "$token_id" '.policies[]? | select([.include[]?.service_token.token_id?] | index($token_id)) | .id' <<<"$app_json")"
  while IFS= read -r policy_id; do
    [[ -n "$policy_id" ]] || continue
    delete_policy "$app_id" "$policy_id"
  done <<<"$policy_ids"

  response="$(cf_api DELETE "/access/service_tokens/${token_id}")"
  jq -e '.success == true' >/dev/null <<<"$response" || {
    echo "ERROR: failed to revoke Cloudflare Access service token ${token_id}" >&2
    jq '{success, errors, messages}' <<<"$response" >&2
    exit 1
  }

  delete_customer_secret "$customer" "cloudflare-access-client-id"
  delete_customer_secret "$customer" "cloudflare-access-client-secret"
  delete_customer_secret "$customer" "cloudflare-access-service-token-id"

  jq -n \
    --arg customer "$customer" \
    --arg hostname "$hostname" \
    --arg token_id "$token_id" \
    '{
      revoked: true,
      customer: $customer,
      hostname: $hostname,
      service_token_id: $token_id
    }'
}

main() {
  local command="${1:-}"

  require_commands

  case "$command" in
    bootstrap)
      bootstrap "${2:-$DEFAULT_HOSTNAME}"
      ;;
    issue)
      issue "${2:-$DEFAULT_CUSTOMER}" "${3:-$DEFAULT_HOSTNAME}"
      ;;
    status)
      status "${2:-$DEFAULT_CUSTOMER}" "${3:-$DEFAULT_HOSTNAME}"
      ;;
    verify)
      verify "${2:-$DEFAULT_CUSTOMER}" "${3:-$DEFAULT_HOSTNAME}"
      ;;
    assert-edge-guard)
      assert_edge_guard "${2:-$DEFAULT_HOSTNAME}"
      ;;
    revoke)
      revoke "${2:-$DEFAULT_CUSTOMER}" "${3:-$DEFAULT_HOSTNAME}"
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
