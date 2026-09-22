#!/usr/bin/env bash
# Shared read-only API listing helper. Source from one of the list-*.sh
# validation scripts; the wrapper supplies the endpoint and API version.

set -euo pipefail

LIST_API_URL="${API_URL:-http://localhost:9080}"
LIST_API_PREFIX="${API_PATH_PREFIX:-/api/rbac}"
LIST_DEFAULT_USER="${RBAC_LIST_USER:-local-v2-org-admin}"
LIST_ORG_ID="local-full-stack"
LIST_ACCOUNT_ID="10001"

list_user_details() {
  case "$1" in
    local-v1-org-admin)
      LIST_USER_ID=local-v1-org-admin-10001
      LIST_IS_ORG_ADMIN=true
      ;;
    local-v1-non-org-admin)
      LIST_USER_ID=local-v1-non-org-admin-10001
      LIST_IS_ORG_ADMIN=false
      ;;
    local-v2-org-admin)
      LIST_USER_ID=local-v2-org-admin-10001
      LIST_IS_ORG_ADMIN=true
      ;;
    local-v2-non-admin)
      LIST_USER_ID=local-v2-non-admin-10001
      LIST_IS_ORG_ADMIN=false
      ;;
    *)
      printf 'ERROR: unknown local user %s\n' "$1" >&2
      printf 'Choose one of the four users loaded by docker-local-full-up.\n' >&2
      return 1
      ;;
  esac
}

list_usage() {
  printf 'Usage: %s [--user USER]\n' "$1"
  printf 'Default user: %s\n' "$LIST_DEFAULT_USER"
  printf 'Allowed users: local-v1-org-admin, local-v1-non-org-admin, '
  printf 'local-v2-org-admin, local-v2-non-admin\n'
}

list_parse_user() {
  local script_name="$1"
  shift
  LIST_USER="$LIST_DEFAULT_USER"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --user)
        [[ $# -ge 2 ]] || { list_usage "$script_name"; return 1; }
        LIST_USER="$2"
        shift 2
        ;;
      --user=*)
        LIST_USER="${1#*=}"
        shift
        ;;
      --help|-h)
        list_usage "$script_name"
        exit 0
        ;;
      *)
        printf 'ERROR: only --user USER is supported.\n' >&2
        list_usage "$script_name" >&2
        return 1
        ;;
    esac
  done
  list_user_details "$LIST_USER"
}

list_rbac_endpoint() {
  local endpoint_label="$1"
  local path="$2"
  local method="GET"
  local response_file status identity_json identity_header

  list_user_details "$LIST_USER"
  identity_json=$(jq -cn \
    --arg account_number "$LIST_ACCOUNT_ID" \
    --arg org_id "$LIST_ORG_ID" \
    --arg username "$LIST_USER" \
    --arg user_id "$LIST_USER_ID" \
    --argjson is_org_admin "$LIST_IS_ORG_ADMIN" \
    '{identity: {account_number: $account_number, org_id: $org_id, type: "User", user: {username: $username, user_id: $user_id, is_org_admin: $is_org_admin}}}')
  identity_header=$(printf '%s' "$identity_json" | base64 | tr -d '\n')
  response_file=$(mktemp "${TMPDIR:-/tmp}/rbac-list-endpoint.XXXXXX")
  trap 'rm -f "$response_file"' RETURN

  status=$(curl -sS --connect-timeout 5 --max-time 30 -o "$response_file" -w '%{http_code}' -X "$method" \
    -H "x-rh-identity: $identity_header" \
    "${LIST_API_URL}${LIST_API_PREFIX}${path}")
  if [[ "$status" != 200 ]]; then
    printf 'ERROR: %s returned HTTP %s for user %s\n' "$endpoint_label" "$status" "$LIST_USER" >&2
    cat "$response_file" >&2
    return 1
  fi

  printf '==> %s (user=%s, org=%s)\n' "$endpoint_label" "$LIST_USER" "$LIST_ORG_ID"
  if jq . "$response_file"; then
    return 0
  fi
  cat "$response_file"
}
