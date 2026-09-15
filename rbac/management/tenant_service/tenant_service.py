"""Common objects for tenant services."""

import logging
from typing import NamedTuple, Optional, Protocol, TypeGuard

from django.db import IntegrityError, transaction
from management.group.model import Group
from management.inventory_replicator.inventory_replicator import InventoryReplicator, PartitionKey, ReplicationEvent
from management.inventory_replicator.inventory_replicator import ReplicationEventType
from management.principal.model import Principal
from management.role_binding.model import RoleBindingPrincipal
from management.tenant_mapping.model import TenantMapping
from management.workspace.model import Workspace

from api.models import Tenant, User

logger = logging.getLogger(__name__)


def _is_missing_user_id(user_id: Optional[str]) -> bool:
    return user_id is None or user_id == ""


def _has_user_id(user_id: Optional[str]) -> TypeGuard[str]:
    return user_id is not None and user_id != ""


def _transfer_role_binding_entries(obsolete: Principal, survivor: Principal) -> None:
    """Move direct role-binding entries from obsolete to survivor, or drop them if cross-tenant."""
    if obsolete.tenant_id != survivor.tenant_id:
        deleted, _ = obsolete.role_binding_entries.all().delete()
        if deleted:
            logger.info(
                "Removed %d role binding entries from cross-tenant obsolete principal. obsolete_username=%s",
                deleted,
                obsolete.username,
            )
        return

    for entry in list(obsolete.role_binding_entries.all()):
        RoleBindingPrincipal.objects.get_or_create(
            binding=entry.binding,
            principal=survivor,
            source=entry.source,
        )
        entry.delete()


def _transfer_group_memberships(obsolete: Principal, survivor: Principal, obsolete_groups: list[Group]) -> None:
    for group in obsolete_groups:
        if not group.principals.filter(pk=survivor.pk).exists():
            group.principals.add(survivor)
        group.principals.remove(obsolete)


def _assign_user_id_and_replicate_merge(
    survivor: Principal,
    obsolete_username: str,
    obsolete_user_id: Optional[str],
    obsolete_groups: list[Group],
    user_id: str,
    replicator: Optional[InventoryReplicator],
) -> None:
    survivor.user_id = user_id
    survivor.save()

    tuples_to_add = _group_member_tuples_for_principal(survivor)
    tuples_to_remove = []
    if obsolete_user_id:
        for group in obsolete_groups:
            tuples_to_remove.append(Group.relationship_to_user_id_for_group(str(group.uuid), obsolete_user_id))

    if replicator is not None and (tuples_to_add or tuples_to_remove):
        replicator.replicate(
            ReplicationEvent(
                event_type=ReplicationEventType.ADD_PRINCIPALS_TO_GROUP,
                info={
                    "org_id": str(survivor.tenant.org_id),
                    "merged_from_username": obsolete_username,
                    "merged_into_username": survivor.username,
                    "user_id": user_id,
                },
                partition_key=PartitionKey.byEnvironment(),
                add=tuples_to_add,
                remove=tuples_to_remove,
            )
        )


def merge_obsolete_principal_into_survivor(
    survivor: Principal,
    obsolete: Principal,
    user_id: str,
    replicator: Optional[InventoryReplicator] = None,
) -> None:
    """
    Merge an older principal (has user_id) into the current principal (no user_id).

    The survivor is typically the latest BOP username: it could not receive user_id due to the
    global uniqueness constraint, but may already have been added to groups. Group memberships
    and direct role-binding entries from the obsolete principal are transferred to the survivor
    when both principals are in the same tenant. user_id is assigned to the survivor and the
    obsolete principal is deleted.
    """
    if survivor.pk == obsolete.pk:
        return

    with transaction.atomic():
        obsolete_groups = list(obsolete.group.all())
        obsolete_user_id = obsolete.user_id
        obsolete_username = obsolete.username

        if survivor.tenant_id != obsolete.tenant_id:
            # user_id is globally unique; the survivor keeps the id in their tenant. Groups and
            # role bindings are tenant-scoped and cannot move across tenants.
            logger.warning(
                "Merging principals across tenants; group and role-binding transfer skipped. "
                "survivor_id=%s survivor_username=%s obsolete_id=%s obsolete_username=%s user_id=%s org_id=%s",
                survivor.pk,
                survivor.username,
                obsolete.pk,
                obsolete.username,
                user_id,
                survivor.tenant.org_id,
            )
            _transfer_role_binding_entries(obsolete, survivor)
            obsolete.delete()
            _assign_user_id_and_replicate_merge(
                survivor,
                obsolete_username,
                obsolete_user_id,
                obsolete_groups,
                user_id,
                replicator,
            )
        else:
            _transfer_group_memberships(obsolete, survivor, obsolete_groups)
            _transfer_role_binding_entries(obsolete, survivor)
            obsolete.delete()
            _assign_user_id_and_replicate_merge(
                survivor,
                obsolete_username,
                obsolete_user_id,
                obsolete_groups,
                user_id,
                replicator,
            )

    logger.info(
        "Merged obsolete principal into survivor. obsolete_username=%s survivor_username=%s user_id=%s groups=%d",
        obsolete_username,
        survivor.username,
        user_id,
        survivor.group.count(),
    )


def _group_member_tuples_for_principal(principal: Principal) -> list:
    tuples_to_add = []
    for group in principal.group.all():
        member_tuple = group.relationship_to_principal(principal)
        if member_tuple is not None:
            tuples_to_add.append(member_tuple)
    return tuples_to_add


def _resolve_user_id_conflict(
    survivor: Principal,
    user_id: str,
    replicator: Optional[InventoryReplicator],
) -> None:
    obsolete = Principal.objects.filter(user_id=user_id).exclude(pk=survivor.pk).first()
    if obsolete is None:
        raise IntegrityError(f"user_id={user_id} is already assigned but no obsolete principal was found")
    merge_obsolete_principal_into_survivor(survivor, obsolete, user_id=user_id, replicator=replicator)


def _ensure_principal_with_user_id_in_tenant(
    user: User,
    tenant: Tenant,
    upsert: bool = False,
    replicator: Optional[InventoryReplicator] = None,
):
    created = False
    principal = None

    if upsert:
        try:
            defaults = {"user_id": user.user_id} if user.user_id else {}
            principal, created = Principal.objects.get_or_create(
                username=user.username,
                tenant=tenant,
                defaults=defaults,
            )
        except IntegrityError:
            if not _has_user_id(user.user_id):
                raise
            survivor, _ = Principal.objects.get_or_create(username=user.username, tenant=tenant)
            _resolve_user_id_conflict(survivor, user.user_id, replicator)
            return
    else:
        try:
            principal = Principal.objects.get(username=user.username, tenant=tenant)
        except Principal.DoesNotExist:
            pass
        except Principal.MultipleObjectsReturned:
            logger.warning(
                f"Multiple principals returned for the same username. username={user.username} org_id={tenant.org_id}"
            )

    if created or principal is None:
        return

    if not _has_user_id(user.user_id):
        return

    if principal.user_id == user.user_id:
        return

    obsolete = Principal.objects.filter(user_id=user.user_id).exclude(pk=principal.pk).first()
    if obsolete is not None:
        merge_obsolete_principal_into_survivor(principal, obsolete, user_id=user.user_id, replicator=replicator)
        return

    if not _is_missing_user_id(principal.user_id):
        logger.warning(
            "Principal user_id does not match BOP user_id and no obsolete owner found. "
            "username=%s principal_user_id=%s bop_user_id=%s org_id=%s",
            principal.username,
            principal.user_id,
            user.user_id,
            tenant.org_id,
        )
        return

    principal.user_id = user.user_id
    try:
        principal.save()
    except IntegrityError:
        _resolve_user_id_conflict(principal, user.user_id, replicator)


class BootstrappedTenant(NamedTuple):
    """Tenant information."""

    tenant: Tenant
    mapping: Optional[TenantMapping]
    default_workspace: Optional[Workspace] = None
    root_workspace: Optional[Workspace] = None


class TenantBootstrapService(Protocol):
    """Service for bootstrapping users in tenants."""

    def update_user(
        self,
        user: User,
        upsert: bool = False,
        bootstrapped_tenant: Optional[BootstrappedTenant] = None,
        ready_tenant: bool = True,
    ) -> Optional[BootstrappedTenant]:
        """Bootstrap a user in a tenant."""
        ...

    def new_bootstrapped_tenant(self, org_id: str, account_number: Optional[str] = None) -> BootstrappedTenant:
        """Create a new tenant."""
        ...
