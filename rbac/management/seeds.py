#
# Copyright 2019 Red Hat, Inc.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""Seeds module."""
import concurrent.futures
import logging
from functools import partial

from django.db import connections

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def on_complete(completed_log_message, future):
    """Explicitly close the connection for the thread."""
    connections.close_all()
    logger.info(completed_log_message)


def role_seeding():
    """Update any roles at startup."""
    from management.role.definer import seed_roles

    do_seeding(seed_roles, "role")


def group_seeding():
    """Update platform group at startup."""
    from management.group.definer import seed_group

    do_seeding(seed_group, "group")


def permission_seeding():
    """Update platform group at startup."""
    from management.role.definer import seed_permissions

    do_seeding(seed_permissions, "permission")


def do_seeding(seed_function, target):
    """General function for seeding."""
    from api.models import Tenant
    from rbac.settings import MAX_SEED_THREADS

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SEED_THREADS) as executor:
            tenants = Tenant.objects.all()
            tenant_count = tenants.count()
            for idx, tenant in enumerate(list(tenants)):
                if tenant.schema_name != "public":
                    logger.info(
                        f"Seeding {target} changes for tenant " f"{tenant.schema_name} [{idx + 1} of {tenant_count}]."
                    )
                    future = executor.submit(seed_function, tenant, update=True)
                    completed_log_message = (
                        f"Finished seeding {target} changes for tenant "
                        f"{tenant.schema_name} [{idx + 1} of {tenant_count}]."
                    )
                    future.add_done_callback(partial(on_complete, completed_log_message))
    except Exception as exc:
        logger.error(f"Error encountered during {target} seeding {exc}.")
