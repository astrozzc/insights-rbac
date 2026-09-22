#!/usr/bin/env bash
# List every RBAC tenant, principals, V2 roles, and role bindings from the
# running local container.
#
# This is a read-only diagnostic action. It uses Django's ORM inside the RBAC
# container so the output reflects the database used by the running stack.
#
# Usage:
#   scripts/validations/api/actions/list-rbac-users.sh
#
# Environment:
#   RBAC_SERVER_CONTAINER  RBAC container name
#                          (default: full-kessel-rbac-server-1)
#   CONTAINER_RUNTIME      docker or podman (auto-detected)
#   COLOR                  auto, always, or never (default: auto)
#   NO_COLOR               disable colors when set
#
# Generate a local test identity instead of listing users:
#   scripts/validations/api/actions/list-rbac-users.sh generate-user --admin --v2

set -euo pipefail

RBAC_SERVER_CONTAINER="${RBAC_SERVER_CONTAINER:-full-kessel-rbac-server-1}"
API_URL="${API_URL:-http://localhost:9080}"
API_PREFIX="${API_PATH_PREFIX:-/api/rbac}"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

show_help() {
  cat <<'EOF'
Usage: list-rbac-users.sh

List every RBAC organization, its persisted principals, V2 roles, and role
bindings from the running local full-stack RBAC container. This action is
read-only.

Environment:
  RBAC_SERVER_CONTAINER  RBAC container name
                         (default: full-kessel-rbac-server-1)
  CONTAINER_RUNTIME      docker or podman (auto-detected)
  COLOR                  auto, always, or never (default: auto)
  NO_COLOR               disable colors when set

Commands:
  list (default)          list persisted organizations and principals
  generate-user           print a header-only identity for API testing

To create persisted users, bootstrap a tenant, and configure groups/roles,
use the sibling action:
  scripts/validations/api/actions/apply-rbac-users-config.sh

generate-user options:
  --admin                 generate an org-admin identity
  --non-admin             generate a non-admin identity (default)
  --v1                    print a V1 API example
  --v2                    print a V2 API example (default)
  --org-id ID             organization ID (default: 11111)
  --account-number NUM    account number (default: 10001)
  --username NAME         username (default: local-user-<generated-id>)
  --user-id ID            user ID (default: generated value)
EOF
}

COMMAND="${1:-list}"
if [[ "$COMMAND" != list ]]; then
  shift
fi

case "$COMMAND" in
  list) ;;
  generate-user) ;;
  --help|-h)
    show_help
    exit 0
    ;;
  *)
    die "unknown command '$COMMAND' (use --help for usage)"
    ;;
esac

detect_runtime() {
  if [[ -n "${CONTAINER_RUNTIME:-}" ]]; then
    return
  fi

  if command -v docker >/dev/null 2>&1 && docker container inspect "$RBAC_SERVER_CONTAINER" >/dev/null 2>&1; then
    CONTAINER_RUNTIME=docker
  elif command -v podman >/dev/null 2>&1 && podman container inspect "$RBAC_SERVER_CONTAINER" >/dev/null 2>&1; then
    CONTAINER_RUNTIME=podman
  else
    die "RBAC container '$RBAC_SERVER_CONTAINER' is not available. Start the local full stack first."
  fi
}

COLOR_ENABLED=false
if [[ -z "${NO_COLOR+x}" && "${COLOR:-auto}" != never ]]; then
  if [[ "${COLOR:-auto}" == always || ( "${COLOR:-auto}" == auto && -t 1 ) ]]; then
    COLOR_ENABLED=true
  fi
fi

if [[ "$COMMAND" == generate-user ]]; then
  USER_ORG_ID="11111"
  USER_ACCOUNT_NUMBER="10001"
  USERNAME=""
  USER_ID=""
  USER_IS_ADMIN=false
  USER_API_VERSION="v2"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --admin)
        USER_IS_ADMIN=true
        ;;
      --non-admin)
        USER_IS_ADMIN=false
        ;;
      --v1)
        USER_API_VERSION="v1"
        ;;
      --v2)
        USER_API_VERSION="v2"
        ;;
      --org-id)
        shift
        [[ $# -gt 0 ]] || die "--org-id requires a value"
        USER_ORG_ID="$1"
        ;;
      --account-number)
        shift
        [[ $# -gt 0 ]] || die "--account-number requires a value"
        USER_ACCOUNT_NUMBER="$1"
        ;;
      --username)
        shift
        [[ $# -gt 0 ]] || die "--username requires a value"
        USERNAME="$1"
        ;;
      --user-id)
        shift
        [[ $# -gt 0 ]] || die "--user-id requires a value"
        USER_ID="$1"
        ;;
      --help|-h)
        show_help
        exit 0
        ;;
      *)
        die "unknown generate-user option '$1' (use --help for usage)"
        ;;
    esac
    shift
  done

  USER_ID="${USER_ID:-$(date +%s)$$}"
  USERNAME="${USERNAME:-local-user-${USER_ID}}"
  USER_EMAIL="${USERNAME}@example.com"
  IDENTITY_JSON=$(jq -cn \
    --arg account_number "$USER_ACCOUNT_NUMBER" \
    --arg org_id "$USER_ORG_ID" \
    --arg username "$USERNAME" \
    --arg email "$USER_EMAIL" \
    --arg user_id "$USER_ID" \
    --argjson is_org_admin "$USER_IS_ADMIN" \
    '{identity: {account_number: $account_number, org_id: $org_id, type: "User", user: {username: $username, email: $email, is_org_admin: $is_org_admin, user_id: $user_id}}}')
  IDENTITY_HEADER=$(printf '%s' "$IDENTITY_JSON" | base64 | tr -d '\n')

  if [[ "$COLOR_ENABLED" == true ]]; then
    CYAN=$'\033[36m'
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    RESET=$'\033[0m'
  else
    CYAN=""
    GREEN=""
    YELLOW=""
    RESET=""
  fi

  printf '%sGenerated local test identity%s\n' "$CYAN" "$RESET"
  printf '  API version: %s%s%s\n' "$YELLOW" "$USER_API_VERSION" "$RESET"
  printf '  Admin:       %s%s%s\n' "$YELLOW" "$USER_IS_ADMIN" "$RESET"
  printf '  Username:    %s\n' "$USERNAME"
  printf '  User ID:     %s\n' "$USER_ID"
  printf '  Org ID:      %s\n' "$USER_ORG_ID"
  printf '\n%sIdentity JSON%s\n%s\n' "$GREEN" "$RESET" "$IDENTITY_JSON"
  printf '\n%sX-RH-Identity value%s\n%s\n' "$GREEN" "$RESET" "$IDENTITY_HEADER"
  printf '\n%sExample request%s\n' "$GREEN" "$RESET"
  printf "curl -sS -H 'x-rh-identity: %s' '%s%s/%s/principals/'\n" \
    "$IDENTITY_HEADER" "$API_URL" "$API_PREFIX" "$USER_API_VERSION"
  printf '\nThis generates an identity header only; it does not create a database user,\n'
  printf 'bootstrap a tenant, or grant Kessel permissions. To persist this kind of\n'
  printf 'fixture, use actions/apply-rbac-users-config.sh.\n'
  exit 0
fi

detect_runtime

"$CONTAINER_RUNTIME" exec \
  -e RBAC_ACTION_COLOR_ENABLED="$COLOR_ENABLED" \
  "$RBAC_SERVER_CONTAINER" \
  python /opt/rbac/rbac/manage.py shell --verbosity 0 -c '
import os

from api.models import Tenant
from management.role.v2_model import RoleV2
from management.role_binding.model import RoleBinding

COLORS = {
    "cyan": "\033[36m",
    "green": "\033[32m",
    "reset": "\033[0m",
    "yellow": "\033[33m",
}


def color(text, name):
    if os.environ.get("RBAC_ACTION_COLOR_ENABLED") != "true":
        return text
    reset = COLORS["reset"]
    return f"{COLORS[name]}{text}{reset}"


tenants = Tenant.objects.order_by("org_id", "tenant_name")
print(color("RBAC tenants and principals", "cyan"))
print(color("===========================", "cyan"))
tenant_count_label = color("Tenants:", "yellow")
print(f"{tenant_count_label} {tenants.count()}")

for tenant in tenants:
    principals = tenant.principal_set.order_by("username")
    org_id = tenant.org_id or "<none>"
    account_id = tenant.account_id or "<none>"
    print()
    print(color(f"ORG {org_id}", "green"))
    tenant_name_label = color("tenant_name:", "cyan")
    account_id_label = color("account_id:", "cyan")
    principals_label = color("principals:", "cyan")
    print(f"  {tenant_name_label} {tenant.tenant_name}")
    print(f"  {account_id_label}  {account_id}")
    print(f"  {principals_label}  {principals.count()}")
    for principal in principals:
        print(
            "    "
            + color("-", "green")
            + " username={username} user_id={user_id} type={type} uuid={uuid}".format(
                username=principal.username,
                user_id=principal.user_id or "<none>",
                type=principal.type,
                uuid=principal.uuid,
            )
        )

    roles = RoleV2.objects.filter(tenant=tenant).prefetch_related("permissions").order_by("name")
    print()
    print(color(f"  roles: {roles.count()}", "cyan"))
    for role in roles:
        permissions = sorted(permission.v2_string() for permission in role.permissions.all())
        permission_text = ", ".join(permissions) if permissions else "<none>"
        print(
            "    "
            + color("-", "green")
            + " name={name} uuid={uuid} type={type} permissions=[{permissions}]".format(
                name=role.name,
                uuid=role.uuid,
                type=role.type,
                permissions=permission_text,
            )
        )

    bindings = (
        RoleBinding.objects.filter(tenant=tenant)
        .select_related("role")
        .prefetch_related("principal_entries__principal", "group_entries__group")
        .order_by("role__name", "resource_type", "resource_id", "uuid")
    )
    print()
    print(color(f"  role_bindings: {bindings.count()}", "cyan"))
    for binding in bindings:
        subjects = [
            "user:{username}({user_id})".format(
                username=entry.principal.username,
                user_id=entry.principal.user_id or "<none>",
            )
            for entry in binding.principal_entries.all()
        ]
        subjects.extend(
            "group:{name}".format(name=entry.group.name) for entry in binding.group_entries.all()
        )
        subject_text = ", ".join(sorted(subjects)) if subjects else "<none>"
        print(
            "    "
            + color("-", "green")
            + " uuid={uuid} role={role} resource={resource_type}:{resource_id} subjects=[{subjects}]".format(
                uuid=binding.uuid,
                role=binding.role.name,
                resource_type=binding.resource_type,
                resource_id=binding.resource_id,
                subjects=subject_text,
            )
        )
'
