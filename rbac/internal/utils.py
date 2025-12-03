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
from typing import Optional

import jsonschema
from django.conf import settings
from django.db import transaction
from django.urls import resolve
from google.protobuf import json_format
from internal.schemas import INVENTORY_INPUT_SCHEMAS, RELATION_INPUT_SCHEMAS
from jsonschema import validate
from kessel.relations.v1beta1 import common_pb2, relation_tuples_pb2
from management.models import BindingMapping, Role, Workspace
from management.relation_replicator.logging_replicator import stringify_spicedb_relationship
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import PartitionKey, ReplicationEvent, ReplicationEventType
from management.workspace.relation_api_dual_write_workspace_handler import RelationApiDualWriteWorkspaceHandler

from api.models import User


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


def replicate_missing_binding_tuples(binding_ids: Optional[list[int]] = None) -> dict:
    """
    Replicate all tuples for specified bindings to fix missing relationships in Kessel.

    This fixes bindings created before REPLICATION_TO_RELATION_ENABLED=True that are missing
    base tuples (t_role and t_binding) in Kessel.

    Args:
        binding_ids (list[int], optional): List of binding IDs to fix. If None, fixes ALL bindings.

    Returns:
        dict: Results with bindings_checked, bindings_fixed, and tuples_added count.
    """
    logger = logging.getLogger(__name__)

    # Get bindings to fix
    if binding_ids:
        bindings_query = BindingMapping.objects.filter(id__in=binding_ids)
        logger.info(f"Fixing {len(binding_ids)} specific bindings: {binding_ids}")
    else:
        bindings_query = BindingMapping.objects.all()
        logger.warning(f"Fixing ALL bindings ({bindings_query.count()} total) - this may take a while")

    bindings_checked = 0
    bindings_fixed = 0
    total_tuples = 0

    # Process each binding in a separate transaction with locking
    for raw_binding in bindings_query.prefetch_related("role").iterator(chunk_size=2000):
        with transaction.atomic():
            # Custom roles must be locked, since other code that updates them locks only the role (and not the binding).
            if not raw_binding.role.system:
                locked_role = Role.objects.select_for_update().filter(pk=raw_binding.role.pk).first()

                if locked_role is None:
                    logger.warning(
                        f"Role vanished before its binding could be fixed: binding pk={raw_binding.pk!r}, "
                        f"role pk={raw_binding.role.pk!r}"
                    )

                    continue

            # Lock the binding to prevent concurrent modifications
            binding = BindingMapping.objects.select_for_update().filter(pk=raw_binding.pk).first()

            if binding is None:
                logger.warning(f"Binding vanished before it could be fixed: pk={raw_binding.pk!r}")
                continue

            bindings_checked += 1

            # Get ALL tuples for this binding (t_role, t_binding, and all subject tuples)
            # Kessel/SpiceDB handles duplicates gracefully, so it's safe to replicate existing tuples
            all_tuples = binding.as_tuples()

            # Replicate ALL tuples - any that already exist will be handled as duplicates
            replicator = OutboxReplicator()
            replicator.replicate(
                ReplicationEvent(
                    event_type=ReplicationEventType.REMIGRATE_ROLE_BINDING,
                    info={
                        "binding_id": binding.id,
                        "role_uuid": str(binding.role.uuid),
                        "org_id": str(binding.role.tenant.org_id),
                        "fix": "missing_binding_tuples",
                    },
                    partition_key=PartitionKey.byEnvironment(),
                    add=all_tuples,
                )
            )

            bindings_fixed += 1
            total_tuples += len(all_tuples)

        # Log progress for large batches (outside transaction)
        if bindings_checked % 100 == 0:
            logger.info(f"Progress: {bindings_checked} bindings processed, {total_tuples} tuples added")

    results = {
        "bindings_checked": bindings_checked,
        "bindings_fixed": bindings_fixed,
        "tuples_added": total_tuples,
    }

    logger.info(f"Completed: Fixed {bindings_fixed} bindings with {total_tuples} total tuples")

    return results


def clean_invalid_workspace_resource_definitions(dry_run: bool = False) -> dict:
    """
    Clean resource definitions with invalid workspace IDs and update bindings accordingly.

    This finds custom roles with resource definitions pointing to non-existent workspaces,
    removes invalid workspace IDs, and uses the dual write handler to update bindings.

    Args:
        dry_run (bool): If True, only report what would be changed without making changes.

    Returns:
        dict: Results with roles_checked, resource_definitions_fixed, and changes list.
    """
    logger = logging.getLogger(__name__)
    from management.role.relation_api_dual_write_handler import RelationApiDualWriteHandler
    from management.relation_replicator.relation_replicator import ReplicationEventType

    roles_checked = 0
    resource_defs_fixed = 0
    changes = []

    if dry_run:
        logger.info("DRY RUN MODE - No changes will be made")

    # Get all custom roles with resource definitions
    custom_roles_with_rds = Role.objects.filter(system=False, access__resourceDefinitions__isnull=False).distinct()

    for raw_role in custom_roles_with_rds.iterator():
        role_had_invalid_rds = False

        with transaction.atomic():
            # Lock the role to prevent concurrent modifications
            role = Role.objects.select_for_update().filter(pk=raw_role.pk).first()

            if role is None:
                logger.warning(f"Role vanished before it could be cleaned: pk={raw_role.pk!r}")
                continue

            roles_checked += 1

            dual_write = RelationApiDualWriteHandler(role, ReplicationEventType.FIX_RESOURCE_DEFINITIONS)
            dual_write.prepare_for_update()

            for access in role.access.all():
                permission = access.permission

                # Only check workspace-related resource definitions
                for rd in access.resourceDefinitions.all():
                    if not is_resource_a_workspace(
                        permission.application, permission.resource_type, rd.attributeFilter
                    ):
                        continue

                    # Get workspace IDs from resource definition
                    workspace_ids = get_workspace_ids_from_resource_definition(rd.attributeFilter)

                    # Check if the resource definition has None (for ungrouped workspace)
                    operation = rd.attributeFilter.get("operation")
                    original_value = rd.attributeFilter.get("value")
                    has_none_value = False

                    if operation == "in" and isinstance(original_value, list):
                        has_none_value = None in original_value
                    elif operation == "equal":
                        has_none_value = original_value is None

                    if not workspace_ids:
                        continue

                    # Check which workspaces exist in the role's tenant
                    valid_workspace_ids = set(
                        str(ws_id)
                        for ws_id in Workspace.objects.filter(id__in=workspace_ids, tenant=role.tenant).values_list(
                            "id", flat=True
                        )
                    )

                    invalid_workspace_ids = set(str(ws_id) for ws_id in workspace_ids) - valid_workspace_ids

                    if invalid_workspace_ids:
                        role_had_invalid_rds = True

                        # Calculate what the new value would be
                        operation_type = rd.attributeFilter.get("operation")
                        new_value: str | list | None
                        if operation_type == "equal":
                            # For "equal" operation, value should be a single string, None, or empty string
                            # Preserve None if it existed (for ungrouped workspace reference)
                            if has_none_value and not valid_workspace_ids:
                                new_value = None
                            else:
                                new_value = list(valid_workspace_ids)[0] if valid_workspace_ids else ""
                        else:
                            # For "in" operation, value should be a list
                            # Preserve None value if it existed (for ungrouped workspace reference)
                            new_value_list: list[str | None] = list(valid_workspace_ids) if valid_workspace_ids else []
                            if has_none_value:
                                new_value_list.append(None)
                            new_value = new_value_list

                        change_info = {
                            "role_uuid": str(role.uuid),
                            "role_name": role.name,
                            "permission": permission.permission,
                            "resource_definition_id": rd.id,
                            "operation": operation_type,
                            "original_value": original_value,
                            "new_value": new_value,
                            "invalid_workspaces": list(invalid_workspace_ids),
                            "valid_workspaces": list(valid_workspace_ids),
                            "preserved_none": has_none_value,
                        }

                        if dry_run:
                            logger.info(
                                f"[DRY RUN] Would update role '{role.name}' (uuid={role.uuid}), "
                                f"permission '{permission.permission}', RD #{rd.id}:\n"
                                f"  Original value: {original_value}\n"
                                f"  New value: {new_value}\n"
                                f"  Invalid workspace IDs removed: {list(invalid_workspace_ids)}\n"
                                f"  Valid workspace IDs kept: {list(valid_workspace_ids)}\n"
                                f"  None preserved: {has_none_value}"
                            )
                            change_info["action"] = "would_update"
                        else:
                            # Update resource definition to remove invalid workspace IDs
                            # Create new dict to ensure Django detects the change (JSONField mutation issue)
                            updated_filter = rd.attributeFilter.copy()
                            updated_filter["value"] = new_value

                            rd.attributeFilter = updated_filter
                            rd.save()
                            resource_defs_fixed += 1
                            change_info["action"] = "updated"

                            logger.info(
                                f"Updated role '{role.name}' (uuid={role.uuid}), "
                                f"permission '{permission.permission}', RD #{rd.id}: "
                                f"{original_value} -> {new_value}"
                            )

                        changes.append(change_info)

            # If we fixed any resource definitions, trigger dual write to update bindings
            if role_had_invalid_rds and not dry_run:
                dual_write.replicate_new_or_updated_role(role)  # Update bindings based on new RDs

    results = {
        "roles_checked": roles_checked,
        "resource_definitions_fixed": resource_defs_fixed,
        "changes": changes,
        "dry_run": dry_run,
    }

    if dry_run:
        logger.info(
            f"[DRY RUN] Would clean invalid workspace RDs: "
            f"{len(changes)} RDs would be fixed across {roles_checked} roles"
        )
    else:
        logger.info(f"Cleaned invalid workspace RDs: {resource_defs_fixed} RDs fixed for {len(changes)} permissions")

    return results


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
    if not isinstance(uuid_str, str):
        return False
    if uuid_str is None or not uuid_str:
        return False
    try:
        uuid.UUID(uuid_str)
        return True
    except ValueError:
        return False


# ============================================================================
# Helper functions for Kessel relationship cleanup
# ============================================================================


def response_to_relationship(r):
    """Convert a gRPC response tuple to a Relationship protobuf."""
    return common_pb2.Relationship(
        resource=common_pb2.ObjectReference(
            type=common_pb2.ObjectType(
                namespace=r.resource.type.namespace,
                name=r.resource.type.name,
            ),
            id=r.resource.id,
        ),
        relation=r.relation,
        subject=common_pb2.SubjectReference(
            subject=common_pb2.ObjectReference(
                type=common_pb2.ObjectType(
                    namespace=r.subject.subject.type.namespace,
                    name=r.subject.subject.type.name,
                ),
                id=r.subject.subject.id,
            ),
            relation=r.subject.relation if r.subject.relation else "",
        ),
    )


def find_group_member_relations(stub, group_uuid: str, metadata: list) -> list:
    """Find member relations for a group."""
    member_filter = relation_tuples_pb2.RelationTupleFilter(
        resource_namespace="rbac",
        resource_type="group",
        resource_id=str(group_uuid),
        relation="member",
    )
    request = relation_tuples_pb2.ReadTuplesRequest(filter=member_filter)
    return list(stub.ReadTuples(request, metadata=metadata))


def find_group_subject_relations(stub, group_uuid: str, metadata: list) -> list:
    """Find subject relations where group is subject."""
    subject_filter = relation_tuples_pb2.RelationTupleFilter(
        subject_filter=relation_tuples_pb2.SubjectFilter(
            subject_namespace="rbac",
            subject_type="group",
            subject_id=str(group_uuid),
        )
    )
    request = relation_tuples_pb2.ReadTuplesRequest(filter=subject_filter)
    return list(stub.ReadTuples(request, metadata=metadata))


def find_role_binding_role_relations(stub, role_uuid: str, metadata: list) -> list:
    """Find role relations for a role."""
    role_filter = relation_tuples_pb2.RelationTupleFilter(
        relation="role",
        subject_filter=relation_tuples_pb2.SubjectFilter(
            subject_namespace="rbac",
            subject_type="role",
            subject_id=str(role_uuid),
        ),
    )
    request = relation_tuples_pb2.ReadTuplesRequest(filter=role_filter)
    return list(stub.ReadTuples(request, metadata=metadata))


def find_role_binding_binding_relations(stub, role_binding_uuid: str, metadata: list) -> list:
    """Find binding relations for a role_binding."""
    binding_filter = relation_tuples_pb2.RelationTupleFilter(
        relation="binding",
        subject_filter=relation_tuples_pb2.SubjectFilter(
            subject_namespace="rbac",
            subject_type="role_binding",
            subject_id=str(role_binding_uuid),
        ),
    )
    request = relation_tuples_pb2.ReadTuplesRequest(filter=binding_filter)
    return list(stub.ReadTuples(request, metadata=metadata))


def find_role_binding_subject_relations(stub, role_binding_uuid: str, metadata: list) -> list:
    """Find subject relations for a role_binding."""
    subject_filter = relation_tuples_pb2.RelationTupleFilter(
        resource_namespace="rbac",
        resource_type="role_binding",
        resource_id=str(role_binding_uuid),
        relation="subject",
    )
    request = relation_tuples_pb2.ReadTuplesRequest(filter=subject_filter)
    return list(stub.ReadTuples(request, metadata=metadata))


def find_role_binding_all_relations(stub, role_binding_uuid: str, metadata: list) -> list:
    """Find all relations for a role_binding (role, binding, subject)."""
    relations = []

    # Role relation: rbac/role_binding:{uuid} #role rbac/role:{uuid}
    role_filter = relation_tuples_pb2.RelationTupleFilter(
        resource_namespace="rbac",
        resource_type="role_binding",
        resource_id=str(role_binding_uuid),
        relation="role",
    )
    role_request = relation_tuples_pb2.ReadTuplesRequest(filter=role_filter)
    relations.extend(stub.ReadTuples(role_request, metadata=metadata))

    # Binding relation: rbac/workspace:{id} #binding rbac/role_binding:{uuid}
    relations.extend(find_role_binding_binding_relations(stub, role_binding_uuid, metadata))

    # Subject relations: rbac/role_binding:{uuid} #subject rbac/group:{uuid}
    relations.extend(find_role_binding_subject_relations(stub, role_binding_uuid, metadata))

    return relations


def cleanup_orphaned_role_bindings(stub, role_binding_uuids: set, metadata: list) -> list:
    """Find all relationships for orphaned role_bindings to remove."""
    relationships_to_remove = []

    for rb_uuid in role_binding_uuids:
        # Get binding relations
        for rel in find_role_binding_binding_relations(stub, rb_uuid, metadata):
            relationships_to_remove.append(response_to_relationship(rel))

        # Get subject relations
        for rel in find_role_binding_subject_relations(stub, rb_uuid, metadata):
            relationships_to_remove.append(response_to_relationship(rel))

        logger.info(f"Added binding and subject relationships for orphaned role_binding {rb_uuid}")

    return relationships_to_remove


def cleanup_orphaned_role(stub, role_uuid: str, metadata: list) -> tuple:
    """Find all relationships for an orphaned role to remove.

    Returns: (role_binding_relations, relationships_to_remove, orphaned_role_binding_uuids)
    """
    role_binding_relations = []
    relationships_to_remove = []
    orphaned_role_bindings = set()

    # Find role_bindings that reference this role
    for r in find_role_binding_role_relations(stub, role_uuid, metadata):
        role_binding_relations.append(json_format.MessageToDict(r))
        orphaned_role_bindings.add(r.resource.id)
        relationships_to_remove.append(response_to_relationship(r))

    # For each orphaned role_binding, clean up all its relationships
    if orphaned_role_bindings:
        relationships_to_remove.extend(cleanup_orphaned_role_bindings(stub, orphaned_role_bindings, metadata))

    return role_binding_relations, relationships_to_remove, list(orphaned_role_bindings)


def resolve_role_info(role_uuid: str | None, role_name: str | None) -> dict:
    """Resolve role information from uuid or name.

    Returns dict with: role_uuid, role_exists, role_is_system, error (if any)
    """
    result = {"role_uuid": role_uuid, "role_exists": False, "role_is_system": False, "error": None}

    # Try to resolve from role_name first
    if role_name and not role_uuid:
        try:
            role = Role.objects.get(name=role_name)
            result["role_uuid"] = str(role.uuid)
            result["role_exists"] = True
            result["role_is_system"] = role.system
            return result
        except Role.DoesNotExist:
            logger.info(f"Role '{role_name}' not found in database")
            return result
        except Role.MultipleObjectsReturned:
            result["error"] = f"Multiple roles found with name '{role_name}'. Please provide role_uuid instead."
            return result

    # Resolve from role_uuid
    if role_uuid:
        try:
            role = Role.objects.get(uuid=role_uuid)
            result["role_exists"] = True
            result["role_is_system"] = role.system
        except Role.DoesNotExist:
            pass

    return result


def cleanup_orphaned_group_scenario(stub, metadata, group_uuid, replicate_removal, result, relationships_to_remove):
    """Handle orphaned group cleanup (group deleted but Kessel relationships remain)."""
    orphaned_role_bindings = set()

    # Find group's member relations (group -> principals)
    member_relations = find_group_member_relations(stub, group_uuid, metadata)
    for r in member_relations:
        result["relations_found"].append(json_format.MessageToDict(r))
        if replicate_removal:
            relationships_to_remove.append(response_to_relationship(r))

    # Find group's subject relations (role_binding -> group)
    subject_relations = find_group_subject_relations(stub, group_uuid, metadata)
    for r in subject_relations:
        result["relations_found"].append(json_format.MessageToDict(r))
        rb_uuid = r.resource.id

        # Check if the role_binding also needs cleanup
        if not BindingMapping.objects.filter(mappings__id=rb_uuid).exists():
            orphaned_role_bindings.add(rb_uuid)

        if replicate_removal:
            relationships_to_remove.append(response_to_relationship(r))

    # Clean up orphaned role_bindings (binding + role relations)
    if replicate_removal and orphaned_role_bindings:
        relationships_to_remove.extend(cleanup_orphaned_role_bindings(stub, orphaned_role_bindings, metadata))

    return orphaned_role_bindings


def cleanup_orphaned_role_scenario(stub, metadata, role_uuid, replicate_removal, result, relationships_to_remove):
    """Handle orphaned role cleanup (role deleted but Kessel relationships remain)."""
    role_binding_rels, role_rels_to_remove, orphaned_rbs = cleanup_orphaned_role(stub, role_uuid, metadata)

    result["relations_found"].extend(role_binding_rels)
    result["orphaned_roles_cleaned"].append(role_uuid)

    if replicate_removal:
        relationships_to_remove.extend(role_rels_to_remove)

    return set(orphaned_rbs)


def cleanup_group_role_assignment_scenario(
    stub,
    metadata,
    group_uuid,
    role_uuid,
    role_name,
    role_exists,
    role_is_system,
    group_exists,
    replicate_removal,
    result,
    relationships_to_remove,
):
    """Handle orphaned group-role assignment cleanup.

    This handles the case where a role was unassigned from a group but the Kessel
    relationship remains. For system roles, we only remove the subject relation
    since system roles have thousands of bindings.
    """
    orphaned_role_bindings = set()

    # Find all role_bindings where this group is a subject
    subject_relations = find_group_subject_relations(stub, group_uuid, metadata)

    for r in subject_relations:
        rb_uuid = r.resource.id
        result["relations_found"].append(json_format.MessageToDict(r))

        # Find which role this binding is for
        role_relations = list(
            stub.ReadTuples(
                relation_tuples_pb2.ReadTuplesRequest(
                    filter=relation_tuples_pb2.RelationTupleFilter(
                        resource_namespace="rbac",
                        resource_type="role_binding",
                        resource_id=rb_uuid,
                        relation="role",
                    )
                ),
                metadata=metadata,
            )
        )

        for role_rel in role_relations:
            bound_role_uuid = role_rel.subject.subject.id

            # Skip if looking for a specific role and this isn't it
            if role_uuid and bound_role_uuid != role_uuid:
                continue

            # Handle case: searching by role_name for a non-existent role
            if role_name and not role_uuid:
                if not Role.objects.filter(uuid=bound_role_uuid).exists():
                    logger.info(f"Found role_binding {rb_uuid} to non-existent role {bound_role_uuid}")
                    orphaned_role_bindings.add(rb_uuid)

                    if replicate_removal:
                        relationships_to_remove.append(response_to_relationship(r))
                        # Also clean up the orphaned role's relationships
                        _, role_rels, _ = cleanup_orphaned_role(stub, bound_role_uuid, metadata)
                        relationships_to_remove.extend(role_rels)
                        result["orphaned_roles_cleaned"].append(bound_role_uuid)
                continue

            # Handle case: specific role found - remove the subject relation
            if replicate_removal:
                relationships_to_remove.append(response_to_relationship(r))

            # If the role doesn't exist AND is not a system role, clean up its bindings
            # System roles have thousands of bindings, so we skip searching them
            if not role_exists and not role_is_system:
                orphaned_role_bindings.add(rb_uuid)
                _, role_rels, _ = cleanup_orphaned_role(stub, role_uuid, metadata)
                relationships_to_remove.extend(role_rels)
                if role_uuid not in result["orphaned_roles_cleaned"]:
                    result["orphaned_roles_cleaned"].append(role_uuid)

    # If group doesn't exist, also clean up its member relations
    if not group_exists:
        member_relations = find_group_member_relations(stub, group_uuid, metadata)
        for r in member_relations:
            result["relations_found"].append(json_format.MessageToDict(r))
            if replicate_removal:
                relationships_to_remove.append(response_to_relationship(r))

    return orphaned_role_bindings
