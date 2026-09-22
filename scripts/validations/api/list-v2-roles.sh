#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/list-rbac-endpoint.bash
source "${SCRIPT_DIR}/lib/list-rbac-endpoint.bash"
list_parse_user "$0" "$@"
list_rbac_endpoint 'V2 roles' '/v2/roles/?limit=100'
