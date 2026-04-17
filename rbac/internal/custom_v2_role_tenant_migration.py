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

"""Backfill rbac/role#owner@rbac/tenant for custom V2 roles from each role's tenant row."""

from __future__ import annotations

import logging
from typing import Any

from django.conf import settings
from management.atomic_transactions import atomic_block
from management.relation_replicator.noop_replicator import NoopReplicator
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import (
    PartitionKey,
    RelationReplicator,
    ReplicationEvent,
    ReplicationEventType,
)
from management.role.relations import role_owner_relationship
from management.role.v2_model import RoleV2

logger = logging.getLogger(__name__)

DEFAULT_CHUNK_SIZE = 500


def _base_queryset(org_id: str | None):
    qs = RoleV2.objects.filter(type=RoleV2.Types.CUSTOM).select_related("tenant").order_by("pk")
    if org_id:
        qs = qs.filter(tenant__org_id=org_id)
    return qs


def _process_chunk(
    *,
    chunk: list[RoleV2],
    dry_run: bool,
    replicator: RelationReplicator,
    replicated: list[dict[str, str]],
    skipped: list[dict[str, str]],
) -> None:
    for role in chunk:
        tenant = role.tenant
        resource_id = tenant.tenant_resource_id()
        if not resource_id:
            skipped.append(
                {
                    "uuid": str(role.uuid),
                    "name": role.name,
                    "reason": "tenant has no tenant_resource_id",
                }
            )
            continue

        if dry_run:
            replicated.append(
                {
                    "uuid": str(role.uuid),
                    "name": role.name,
                    "org_id": str(tenant.org_id) if tenant.org_id else "",
                }
            )
            continue

        replicator.replicate(
            ReplicationEvent(
                event_type=ReplicationEventType.UPDATE_CUSTOM_ROLE,
                info={
                    "role_uuid": str(role.uuid),
                    "org_id": str(tenant.org_id) if tenant.org_id else "",
                },
                partition_key=PartitionKey.byEnvironment(),
                add=[role_owner_relationship(role.uuid, resource_id)],
                remove=[],
            )
        )
        logger.info(
            "Replicated owner tuple for custom V2 role uuid=%s name=%r tenant org_id=%s",
            role.uuid,
            role.name,
            tenant.org_id,
        )
        replicated.append(
            {
                "uuid": str(role.uuid),
                "name": role.name,
                "org_id": str(tenant.org_id) if tenant.org_id else "",
            }
        )


def replicate_custom_v2_role_owner_relationships(
    *,
    dry_run: bool = False,
    org_id: str | None = None,
    replicator: RelationReplicator | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> dict[str, Any]:
    """Emit owner tuples for every custom V2 role from ``role.tenant.tenant_resource_id()``.

    Does not change PostgreSQL role rows; only replicates ``rbac/role:<uuid>#owner@rbac/tenant:<id>``.

    Roles whose tenant has no resource id (e.g. public tenant or missing org_id) are skipped.

    Fetches and processes in chunks of ``chunk_size`` rows (keyset pagination on ``pk``). Each chunk is read
    and processed inside a separate SERIALIZABLE transaction (see ``atomic_block``). When ``dry_run`` is true,
    the replicator is not called.
    """
    if replicator is None:
        if settings.REPLICATION_TO_RELATION_ENABLED:
            replicator = OutboxReplicator()
        else:
            replicator = NoopReplicator()

    base = _base_queryset(org_id)
    replicated: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []

    last_pk = 0
    while True:
        with atomic_block():
            chunk = list(base.filter(pk__gt=last_pk)[:chunk_size])
            if not chunk:
                break
            last_pk = chunk[-1].pk
            _process_chunk(
                chunk=chunk,
                dry_run=dry_run,
                replicator=replicator,
                replicated=replicated,
                skipped=skipped,
            )

    return {
        "dry_run": dry_run,
        "replicated": replicated,
        "skipped": skipped,
        "replicated_count": len(replicated),
        "skipped_count": len(skipped),
    }
