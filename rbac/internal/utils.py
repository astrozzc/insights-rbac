#
# Copyright 2022 Red Hat, Inc.
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

"""Utilities for Internal RBAC use."""
import json
import logging
import uuid

import jsonschema
from django.conf import settings
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.urls import resolve
from internal.schemas import INVENTORY_INPUT_SCHEMAS, RELATION_INPUT_SCHEMAS
from jsonschema import validate
from management.models import Workspace
from management.relation_replicator.logging_replicator import stringify_spicedb_relationship
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import PartitionKey, ReplicationEvent, ReplicationEventType
from management.workspace.relation_api_dual_write_workspace_handler import RelationApiDualWriteWorkspaceHandler
from migration_tool.utils import create_relationship

from api.models import Tenant, User


logger = logging.getLogger(__name__)


def build_internal_user(request, json_rh_auth):
    """Build user object for internal requests."""
    user = User()
    valid_identity_types = ["Associate", "X509"]
    try:
        identity_type = json_rh_auth["identity"]["type"]
        if identity_type not in valid_identity_types:
            logger.debug(
                f"User identity type is not valid: '{identity_type}'. Valid types are: {valid_identity_types}"
            )
            return None
        user.username = json_rh_auth["identity"].get("associate", {}).get("email", "system")
        user.admin = True
        user.org_id = resolve(request.path).kwargs.get("org_id")
        return user
    except KeyError:
        logger.debug(
            f"Identity object is missing 'identity.type' attribute. Valid options are: {valid_identity_types}"
        )
        return None


def delete_bindings(bindings):
    """
    Delete the provided bindings and replicate the deletion event.

    Args:
        bindings (QuerySet): A Django QuerySet of binding objects to be deleted.

    Returns:
        dict: A dictionary containing information about the deleted bindings, including:
            - mappings (list): A list of mappings for each binding.
            - role_ids (list): A list of role IDs for each binding.
            - resource_ids (list): A list of resource IDs for each binding.
            - resource_types (list): A list of resource type names for each binding.
            - relations (list): A list of tuples representing the relations to be removed.
    """
    replicator = OutboxReplicator()
    # Get org_id from first binding's role tenant
    org_id = str(bindings.first().role.tenant.org_id) if bindings.exists() else ""
    info = {
        "mappings": [binding.mappings for binding in bindings],
        "role_ids": [binding.role_id for binding in bindings],
        "resource_ids": [binding.resource_id for binding in bindings],
        "resource_types": [binding.resource_type_name for binding in bindings],
        "org_id": org_id,
    }
    if bindings:
        with transaction.atomic():
            relations_to_remove = []
            for binding in bindings:
                relations_to_remove.extend(binding.as_tuples())
            replicator.replicate(
                ReplicationEvent(
                    event_type=ReplicationEventType.DELETE_BINDING_MAPPINGS,
                    info=info,
                    partition_key=PartitionKey.byEnvironment(),
                    remove=relations_to_remove,
                ),
            )
            bindings.delete()
        info["relations"] = [stringify_spicedb_relationship(relation) for relation in relations_to_remove]
    return info


@transaction.atomic
def get_or_create_ungrouped_workspace(tenant: str) -> Workspace:
    """
    Retrieve the ungrouped workspace for the given tenant.

    Args:
        tenant (str): The tenant for which to retrieve the ungrouped workspace.
    Returns:
        Workspace: The ungrouped workspace object for the given tenant.
    """
    # fetch parent only once
    default_ws = Workspace.objects.get(tenant=tenant, type=Workspace.Types.DEFAULT)

    # single select_for_update + get_or_create
    workspace, created = Workspace.objects.select_for_update().get_or_create(
        tenant=tenant,
        type=Workspace.Types.UNGROUPED_HOSTS,
        defaults={"name": Workspace.SpecialNames.UNGROUPED_HOSTS, "parent": default_ws},
    )

    if created:
        RelationApiDualWriteWorkspaceHandler(
            workspace, ReplicationEventType.CREATE_WORKSPACE
        ).replicate_new_workspace()

    return workspace


def validate_relations_input(action, request_data) -> bool:
    """Check if request body provided to relations tool endpoints are valid."""
    validation_schema = RELATION_INPUT_SCHEMAS[action]
    try:
        validate(instance=request_data, schema=validation_schema)
        logger.info("JSON data is valid.")
        return True
    except jsonschema.exceptions.ValidationError as e:
        logger.info(f"JSON data is invalid: {e.message}")
        return False
    except Exception as e:
        logger.info(f"Exception occurred when validating JSON body: {e}")
        return False


def validate_inventory_input(action, request_data) -> bool:
    """Check if request body provided to inventory tool endpoints are valid."""
    validation_schema = INVENTORY_INPUT_SCHEMAS[action]
    try:
        validate(instance=request_data, schema=validation_schema)
        logger.info("JSON data is valid.")
        return True
    except jsonschema.exceptions.ValidationError as e:
        logger.info(f"JSON data is invalid: {e.message}")
        return False
    except Exception as e:
        logger.info(f"Exception occurred when validating JSON body: {e}")
        return False


def load_request_body(request) -> dict:
    """Decode request body from json into dict structure."""
    request_decoded = request.body.decode("utf-8")
    req_data = json.loads(request_decoded)
    return req_data


def is_resource_a_workspace(application: str, resource_type: str, attributeFilter: dict) -> bool:
    """Check if a given ResourceDefinition is a Workspace."""
    is_workspace_application = application == settings.WORKSPACE_APPLICATION_NAME
    is_workspace_resource_type = resource_type in settings.WORKSPACE_RESOURCE_TYPE
    is_workspace_group_filter = attributeFilter.get("key") == settings.WORKSPACE_ATTRIBUTE_FILTER
    return is_workspace_application and is_workspace_resource_type and is_workspace_group_filter


def get_workspace_ids_from_resource_definition(attributeFilter: dict) -> list[uuid.UUID]:
    """Get workspace id from a resource definition."""
    operation = attributeFilter.get("operation")
    ret = []
    if operation == "in":
        value = attributeFilter.get("value", [])
        ret.extend(uuid.UUID(val) for val in value if is_str_valid_uuid(val))
    elif operation == "equal":
        value = attributeFilter.get("value", "")
        if is_str_valid_uuid(value):
            ret.append(uuid.UUID(value))

    return ret


def is_str_valid_uuid(uuid_str: str) -> bool:
    """Check if a string can be converted to a valid UUID."""
    if uuid_str is None or not uuid_str:
        return False
    try:
        uuid.UUID(uuid_str)
        return True
    except ValueError:
        return False


@transaction.atomic
def replicate_workspace_relationships_for_tenant(org_id: str) -> dict:
    """
    Replicate workspace relationships for a single tenant.

    This replicates parent relationships for ungrouped-hosts and standard workspaces.
    Root and default workspace relationships are handled by tenant bootstrap.

    Locking strategy:
    - Locks all workspaces being replicated to prevent concurrent parent updates
    - Ensures the parent relationship cannot change between read and replication
    - Prevents race condition where dual write updates parent while we're replicating old parent

    Args:
        org_id (str): The organization ID of the tenant.

    Returns:
        dict: A dictionary with status and details about the replication:
            - org_id (str): The organization ID
            - status (str): "success" or "error"
            - message (str): Description of the result
            - workspaces_replicated (int): Number of workspace relationships replicated
            - workspace_ids (list): List of workspace UUIDs that had relationships replicated
    """
    tenant = get_object_or_404(Tenant, org_id=org_id)
    logger.info(f"Replicating workspace relationships for tenant: {org_id}")

    # First, get workspace IDs to lock (without select_related to avoid locking parents prematurely)
    workspace_ids_to_lock = list(
        Workspace.objects.filter(tenant=tenant)
        .exclude(type__in=[Workspace.Types.ROOT, Workspace.Types.DEFAULT])
        .values_list("id", flat=True)
    )

    if not workspace_ids_to_lock:
        logger.info(f"No ungrouped or standard workspaces found for tenant {org_id}")
        return {
            "org_id": org_id,
            "status": "success",
            "message": "No ungrouped or standard workspaces found",
            "workspaces_replicated": 0,
        }

    # Lock workspaces to prevent concurrent updates
    # This prevents race condition where parent changes between read and replication
    workspaces = (
        Workspace.objects.select_for_update()
        .filter(id__in=workspace_ids_to_lock)
        .select_related("parent")
    )

    # Collect all unique parent IDs and lock them in one query
    # This is more efficient than locking each parent individually (especially if many share same parent)
    parent_ids = set()
    workspaces_list = list(workspaces)  # Evaluate queryset once
    
    for workspace in workspaces_list:
        if workspace.parent_id is not None:
            parent_ids.add(workspace.parent_id)
    
    if parent_ids:
        # Lock all unique parent workspaces in a single query
        Workspace.objects.select_for_update().filter(id__in=parent_ids).exists()

    relationships = []
    workspace_ids = []

    for workspace in workspaces_list:
        if workspace.parent is None:
            logger.warning(f"Workspace {workspace.id} has no parent, skipping. Type: {workspace.type}")
            continue

        # Parent is already locked (from the batch lock above)
        # Create relationship tuple for this workspace
        relationship = create_relationship(
            ("rbac", "workspace"),
            str(workspace.id),
            ("rbac", "workspace"),
            str(workspace.parent.id),
            "parent",
        )
        relationships.append(relationship)
        workspace_ids.append(str(workspace.id))

    if not relationships:
        logger.info(f"No workspace relationships to replicate for tenant {org_id}")
        return {
            "org_id": org_id,
            "status": "success",
            "message": "No workspace relationships to replicate",
            "workspaces_replicated": 0,
        }

    # Replicate all relationships in one batch
    replicator = OutboxReplicator()
    replicator.replicate(
        ReplicationEvent(
            event_type=ReplicationEventType.WORKSPACE_IMPORT,
            info={"org_id": org_id, "workspace_count": len(relationships)},
            partition_key=PartitionKey.byEnvironment(),
            add=relationships,
        )
    )

    logger.info(
        f"Successfully replicated {len(relationships)} workspace relationships for tenant {org_id}. "
        f"Workspace IDs: {workspace_ids}"
    )

    return {
        "org_id": org_id,
        "status": "success",
        "message": f"Replicated {len(relationships)} workspace relationships",
        "workspaces_replicated": len(relationships),
        "workspace_ids": workspace_ids,
    }
