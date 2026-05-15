#
# Copyright 2026 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

"""Shared utility for checking tenant-level Kessel permissions.

Replaces org_admin privilege checks with Kessel permission checks on the
tenant resource. When the KESSEL_TENANT_PERMISSION_CHECK feature flag is
enabled, the user's access is verified via the Inventory API's CheckForUpdate
gRPC call instead of the identity header's is_org_admin flag.

System users (PSK/token auth) always fall back to user.admin since they
don't have Kessel identities.
"""

import logging

from feature_flags import FEATURE_FLAGS
from management.permissions.system_user_utils import is_system_user
from management.permissions.workspace_inventory_access import WorkspaceInventoryAccessChecker
from management.principal.proxy import get_kessel_principal_id

from rbac.env import ENVIRONMENT

logger = logging.getLogger(__name__)


def check_tenant_kessel_permission(request, relation: str) -> bool:
    """Check if the user has a given permission on their tenant via Kessel.

    When the KESSEL_TENANT_PERMISSION_CHECK feature flag is enabled, this
    function calls the Inventory API to check whether the principal has the
    specified relation on the tenant resource. When the flag is disabled
    (or for system users), it falls back to ``request.user.admin``.

    Args:
        request: The HTTP request object (must have ``tenant`` and ``user``).
        relation: The Kessel relation to check (e.g. ``rbac_roles_read``).

    Returns:
        True if the principal has the permission, False otherwise.
    """
    if ENVIRONMENT.get_value("ALLOW_ANY", default=False, cast=bool):
        return True

    if is_system_user(request.user):
        return getattr(request.user, "admin", False)

    if not FEATURE_FLAGS.is_kessel_tenant_permission_check_enabled():
        return getattr(request.user, "admin", False)

    tenant = getattr(request, "tenant", None)
    if tenant is None:
        logger.debug("Denied %s: no tenant on request", relation)
        return False

    org_resource_id = tenant.tenant_resource_id()
    if not org_resource_id:
        logger.debug("Denied %s: tenant has no resource ID", relation)
        return False

    principal_id = get_kessel_principal_id(request)
    if not principal_id:
        logger.debug("Denied %s: could not determine principal ID", relation)
        return False

    checker = WorkspaceInventoryAccessChecker()
    return checker.check_resource_access(
        resource_type="tenant",
        resource_id=org_resource_id,
        principal_id=principal_id,
        relation=relation,
    )
