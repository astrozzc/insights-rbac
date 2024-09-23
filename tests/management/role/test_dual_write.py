#
# Copyright 2019 Red Hat, Inc.
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
"""Test tuple changes for RBAC operations."""

import unittest
from django.test import TestCase, override_settings
from management.group.model import Group
from management.permission.model import Permission
from management.policy.model import Policy
from management.principal.model import Principal
from management.role.model import Access, ResourceDefinition, Role
from management.role.relation_api_dual_write_handler import RelationApiDualWriteHandler, ReplicationEventType
from migration_tool.in_memory_tuples import (
    InMemoryRelationReplicator,
    InMemoryTuples,
    all_of,
    one_of,
    relation,
    resource,
    resource_id,
    resource_type,
    subject,
    subject_type,
)


from api.models import Tenant


@override_settings(REPLICATION_TO_RELATION_ENABLED=True)
class DualWriteTestCase(TestCase):
    """
    Base TestCase for testing dual write logic.

    Use "given" methods to set up state like users would. Use "expect" methods to assert the state of the system.

    "Given" methods are treated like distinct transactions, which each replicate tuples via dual write.
    """

    def setUp(self):
        """Set up the dual write tests."""
        super().setUp()
        self.tuples = InMemoryTuples()
        self.fixture = RbacFixture()
        self.tenant = self.fixture.new_tenant(name="tenant", org_id="1234567")

    def default_workspace(self) -> str:
        """Return the default workspace ID."""
        assert self.tenant.org_id is not None, "Tenant org_id should not be None"
        return self.tenant.org_id

    def dual_write_handler(self, role: Role, event_type: ReplicationEventType) -> RelationApiDualWriteHandler:
        """Create a RelationApiDualWriteHandler for the given role and event type."""
        return RelationApiDualWriteHandler(role, event_type, replicator=InMemoryRelationReplicator(self.tuples))

    def dual_write_handler_for_system_role(
        self, role: Role, tenant: Tenant, event_type: ReplicationEventType
    ) -> RelationApiDualWriteHandler:
        """Create a RelationApiDualWriteHandler for the given role and event type."""
        return RelationApiDualWriteHandler.for_system_role_event(
            role, tenant, event_type, replicator=InMemoryRelationReplicator(self.tuples)
        )

    def given_v1_system_role(self, name: str, permissions: list[str]) -> Role:
        """Create a new system role with the given ID and permissions."""
        role = self.fixture.new_system_role(name=name, permissions=permissions)
        # TODO: Need to replicate system role permission relations
        # This is different from group assignment
        return role

    def given_v1_role(self, name: str, default: list[str], **kwargs: list[str]) -> Role:
        """Create a new custom role with the given ID and workspace permissions."""
        role = self.fixture.new_custom_role(
            name=name,
            tenant=self.tenant,
            resource_access=self._workspace_access_to_resource_definition(default, **kwargs),
        )
        dual_write = self.dual_write_handler(role, ReplicationEventType.CREATE_CUSTOM_ROLE)
        dual_write.replicate_new_or_updated_role(role)
        return role

    def given_update_to_v1_role(self, role: Role, default: list[str] = [], **kwargs: list[str]):
        """Update the given role with the given workspace permissions."""
        dual_write = self.dual_write_handler(role, ReplicationEventType.UPDATE_CUSTOM_ROLE)
        dual_write.prepare_for_update()
        role = self.fixture.update_custom_role(
            role,
            resource_access=self._workspace_access_to_resource_definition(default, **kwargs),
        )
        dual_write.replicate_new_or_updated_role(role)
        return role

    def _workspace_access_to_resource_definition(self, default: list[str], **kwargs: list[str]):
        return [
            (default, {}),
            *[
                (permissions, {"key": "group.id", "operation": "equal", "value": workspace})
                for workspace, permissions in kwargs.items()
            ],
        ]

    def given_group(self, name: str, users: list[str]) -> Group:
        """Create a new group with the given name and users."""
        # TODO: replicate group membership
        return self.fixture.new_group(name=name, users=users, tenant=self.tenant)

    def given_policy(self, group: Group, roles: list[Role]) -> Policy:
        """Assign the [roles] to the [group]."""
        # TODO: replicate role assignment
        return self.fixture.add_role_to_group(roles[0], group, self.tenant)

    def expect_1_v2_role_with_permissions(self, permissions: list[str]) -> str:
        """Assert there is a role matching the given permissions and return its ID."""
        return self.expect_v2_roles_with_permissions(1, permissions)[0]

    def expect_v2_roles_with_permissions(self, count: int, permissions: list[str]) -> list[str]:
        """Assert there is a role matching the given permissions and return its ID."""
        roles, unmatched = self.tuples.find_group_with_tuples(
            [
                all_of(resource_type("rbac", "role"), relation(permission.replace(":", "_")))
                for permission in permissions
            ],
            group_by=lambda t: (t.resource_type_namespace, t.resource_type_name, t.resource_id),
            group_filter=lambda group: group[0] == "rbac" and group[1] == "role",
            require_full_match=True,
        )

        num_roles = len(roles)
        self.assertEqual(
            num_roles,
            count,
            f"Expected exactly {count} role(s) with permissions {permissions}, but got {num_roles}.\n"
            f"Matched roles: {roles}.\n"
            f"Unmatched roles: {unmatched}",
        )
        return [role[2] for role in roles.keys()]

    def expect_num_role_bindings(self, num: int):
        """Assert there are [num] role bindings."""
        role_bindings = self.tuples.find_tuples_grouped(
            subject_type("rbac", "role_binding"),
            group_by=lambda t: (t.resource_type_namespace, t.resource_type_name, t.resource_id),
        )
        num_role_bindings = len(role_bindings)
        self.assertEqual(
            num_role_bindings,
            num,
            f"Expected exactly {num} role bindings, but got {num_role_bindings}.\n" f"Role bindings: {role_bindings}",
        )

    def expect_1_role_binding_to_workspace(self, workspace: str, for_v2_roles: list[str], for_groups: list[str]):
        """Assert there is a role binding with the given roles and groups."""
        # Find all bindings for the given workspace
        resources = self.tuples.find_tuples_grouped(
            all_of(resource("rbac", "workspace", workspace), relation("user_grant")),
            group_by=lambda t: (t.resource_type_namespace, t.resource_type_name, t.resource_id),
        )

        # Now of those bound to the workspace, find bindings that bind the given roles and groups
        # (we expect only 1)
        role_bindings, unmatched = self.tuples.find_group_with_tuples(
            [
                all_of(
                    resource_type("rbac", "role_binding"),
                    one_of(*[resource_id(t.subject_id) for _, tuples in resources.items() for t in tuples]),
                    relation("granted"),
                    subject("rbac", "role", role_id),
                )
                for role_id in for_v2_roles
            ]
            + [
                all_of(
                    resource_type("rbac", "role_binding"),
                    relation("subject"),
                    subject("rbac", "group", group_id),
                )
                for group_id in for_groups
            ],
            group_by=lambda t: (t.resource_type_namespace, t.resource_type_name, t.resource_id),
            group_filter=lambda group: group[0] == "rbac" and group[1] == "role_binding",
            require_full_match=True,
        )

        num_role_bindings = len(role_bindings)
        self.assertEqual(
            num_role_bindings,
            1,
            f"Expected exactly 1 role binding against workspace {workspace} "
            f"with roles {for_v2_roles} and groups {for_groups}, "
            f"but got {len(role_bindings)}.\n"
            f"Matched role bindings: {role_bindings}.\n"
            f"Unmatched role bindings: {unmatched}",
        )


class DualWriteSystemRolesTestCase(DualWriteTestCase):
    """Test dual write logic for system roles."""

    @unittest.skip("Not implemented yet")
    def test_system_role_grants_access_to_default_workspace(self):
        """Create role binding only when system role is bound to group."""
        role = self.given_v1_system_role("r1", ["app1:hosts:read", "inventory:hosts:write"])
        group = self.given_group("g1", ["u1", "u2"])

        self.expect_num_role_bindings(0)

        self.given_policy(group, roles=[role])

        id = self.expect_1_v2_role_with_permissions(["app1:hosts:read", "inventory:hosts:write"])
        self.expect_1_role_binding_to_workspace(self.default_workspace(), for_v2_roles=[id], for_groups=[group.id])
        self.expect_num_role_bindings(1)


class DualWriteCustomRolesTestCase(DualWriteTestCase):
    """Test dual write logic when we are working with custom roles."""

    def test_role_with_same_default_and_resource_permission_reuses_same_v2_role(self):
        """With same resource permissions (when one of those is the default workspace), reuse the same v2 role."""
        role = self.given_v1_role(
            "r1",
            default=["app1:hosts:read", "inventory:hosts:write"],
            ws_2=["app1:hosts:read", "inventory:hosts:write"],
        )

        group = self.given_group("g1", ["u1", "u2"])
        self.given_policy(group, roles=[role])

        id = self.expect_1_v2_role_with_permissions(["app1:hosts:read", "inventory:hosts:write"])
        # TODO: assert group once group replication is implemented
        self.expect_1_role_binding_to_workspace(self.default_workspace(), for_v2_roles=[id], for_groups=[])
        self.expect_1_role_binding_to_workspace("ws_2", for_v2_roles=[id], for_groups=[])

    def test_add_permissions_to_role(self):
        """Modify the role in place when adding permissions."""
        role = self.given_v1_role(
            "r1",
            default=["app1:hosts:read", "inventory:hosts:write"],
            ws_2=["app1:hosts:read", "inventory:hosts:write"],
        )

        self.given_update_to_v1_role(
            role,
            default=["app1:hosts:read", "inventory:hosts:write"],
            ws_2=["app1:hosts:read", "inventory:hosts:write", "app2:hosts:read"],
        )

        role_for_default = self.expect_1_v2_role_with_permissions(["app1:hosts:read", "inventory:hosts:write"])
        role_for_ws_2 = self.expect_1_v2_role_with_permissions(
            ["app1:hosts:read", "inventory:hosts:write", "app2:hosts:read"]
        )

        # TODO: assert group once group replication is implemented
        self.expect_1_role_binding_to_workspace(
            self.default_workspace(), for_v2_roles=[role_for_default], for_groups=[]
        )
        self.expect_1_role_binding_to_workspace("ws_2", for_v2_roles=[role_for_ws_2], for_groups=[])

    def test_remove_permissions_from_role(self):
        """Modify the role in place when removing permissions."""
        role = self.given_v1_role(
            "r1",
            default=["app1:hosts:read", "inventory:hosts:write"],
            ws_2=["app1:hosts:read", "inventory:hosts:write"],
        )

        self.given_update_to_v1_role(
            role,
            default=["app1:hosts:read", "inventory:hosts:write"],
            ws_2=["app1:hosts:read"],
        )

        role_for_default = self.expect_1_v2_role_with_permissions(["app1:hosts:read", "inventory:hosts:write"])
        role_for_ws_2 = self.expect_1_v2_role_with_permissions(["app1:hosts:read"])

        # TODO: assert group once group replication is implemented
        self.expect_1_role_binding_to_workspace(
            self.default_workspace(), for_v2_roles=[role_for_default], for_groups=[]
        )
        self.expect_1_role_binding_to_workspace("ws_2", for_v2_roles=[role_for_ws_2], for_groups=[])

    def test_remove_permissions_from_role_back_to_original(self):
        """Modify the role in place when removing permissions, consolidating roles."""
        """Modify the role in place when adding permissions."""
        role = self.given_v1_role(
            "r1",
            default=["app1:hosts:read", "inventory:hosts:write"],
            ws_2=["app1:hosts:read", "inventory:hosts:write"],
        )

        self.given_update_to_v1_role(
            role,
            default=["app1:hosts:read", "inventory:hosts:write"],
            ws_2=["app1:hosts:read", "inventory:hosts:write", "app2:hosts:read"],
        )

        self.given_update_to_v1_role(
            role,
            default=["app1:hosts:read", "inventory:hosts:write"],
            ws_2=["app1:hosts:read", "inventory:hosts:write"],
        )

        id = self.expect_1_v2_role_with_permissions(["app1:hosts:read", "inventory:hosts:write"])
        self.expect_1_role_binding_to_workspace(self.default_workspace(), for_v2_roles=[id], for_groups=[])
        self.expect_1_role_binding_to_workspace("ws_2", for_v2_roles=[id], for_groups=[])

    def test_add_resource_uses_existing_groups(self):
        """New bindings get existing groups."""
        role = self.given_v1_role(
            "r1",
            default=["app1:hosts:read", "inventory:hosts:write"],
            ws_2=["app1:hosts:read", "inventory:hosts:write"],
        )

        g1 = self.given_group("g2", ["u2"])
        g2 = self.given_group("g1", ["u1"])
        self.given_policy(g1, roles=[role])
        self.given_policy(g2, roles=[role])

        self.given_update_to_v1_role(
            role,
            default=["app1:hosts:read", "inventory:hosts:write"],
            ws_2=["app1:hosts:read", "inventory:hosts:write"],
            ws_3=["app1:hosts:read", "inventory:hosts:write"],
        )

        role = self.expect_1_v2_role_with_permissions(["app1:hosts:read", "inventory:hosts:write"])

        self.expect_1_role_binding_to_workspace("ws_3", for_v2_roles=[role], for_groups=[str(g1.uuid), str(g2.uuid)])

    def test_delete_role(self):
        """Delete the role and its bindings when deleting a custom role."""
        pass

    def test_remove_resource_removes_role_binding(self):
        """Remove the role binding when removing the resource from attribute filter."""
        role = self.given_v1_role(
            "r1",
            default=["app1:hosts:read", "inventory:hosts:write"],
            ws_2=["app1:hosts:read", "inventory:hosts:write"],
        )

        self.given_update_to_v1_role(
            role,
            ws_2=["app1:hosts:read", "inventory:hosts:write"],
        )

        role = self.expect_1_v2_role_with_permissions(["app1:hosts:read", "inventory:hosts:write"])

        self.expect_num_role_bindings(1)
        self.expect_1_role_binding_to_workspace("ws_2", for_v2_roles=[role], for_groups=[])

    def test_two_roles_with_same_resource_permissions_create_two_v2_roles(self):
        """Create two v2 roles when two roles have the same resource permissions across different resources."""
        self.given_v1_role(
            "r1",
            default=["app1:hosts:read", "inventory:hosts:write"],
            ws_2=["app1:hosts:read", "inventory:hosts:write"],
        )

        self.given_v1_role(
            "r2",
            default=["app1:hosts:read", "inventory:hosts:write"],
            ws_2=["app1:hosts:read", "inventory:hosts:write"],
        )

        roles = self.expect_v2_roles_with_permissions(2, ["app1:hosts:read", "inventory:hosts:write"])

        self.expect_1_role_binding_to_workspace(self.default_workspace(), for_v2_roles=[roles[0]], for_groups=[])
        self.expect_1_role_binding_to_workspace(self.default_workspace(), for_v2_roles=[roles[1]], for_groups=[])
        self.expect_1_role_binding_to_workspace("ws_2", for_v2_roles=[roles[0]], for_groups=[])
        self.expect_1_role_binding_to_workspace("ws_2", for_v2_roles=[roles[1]], for_groups=[])


class RbacFixture:
    """RBAC Fixture."""

    def __init__(self):
        """Initialize the RBAC fixture."""
        self.public_tenant = Tenant.objects.create(tenant_name="public")

    def new_tenant(self, name: str, org_id: str) -> Tenant:
        """Create a new tenant with the given name and organization ID."""
        return Tenant.objects.create(tenant_name=name, org_id=org_id)

    def new_system_role(self, name: str, permissions: list[str]) -> Role:
        """Create a new system role with the given name and permissions."""
        role = Role.objects.create(name=name, system=True, tenant=self.public_tenant)

        access_list = [
            Access(
                permission=Permission.objects.get_or_create(permission=permission, tenant=self.public_tenant)[0],
                role=role,
                tenant=self.public_tenant,
            )
            for permission in permissions
        ]

        Access.objects.bulk_create(access_list)

        return role

    def new_custom_role(self, name: str, resource_access: list[tuple[list[str], dict]], tenant: Tenant) -> Role:
        """
        Create a new custom role.

        [resource_access] is a list of tuples of the form (permissions, attribute_filter).
        """
        role = Role.objects.create(name=name, system=False, tenant=tenant)
        return self.update_custom_role(role, resource_access)

    def update_custom_role(self, role: Role, resource_access: list[tuple[list[str], dict]]) -> Role:
        """
        Update a custom role.

        [resource_access] is a list of tuples of the form (permissions, attribute_filter).
        """
        role.access.all().delete()

        for permissions, attribute_filter in resource_access:
            access_list = [
                Access(
                    permission=Permission.objects.get_or_create(permission=permission, tenant=role.tenant)[0],
                    role=role,
                    tenant=role.tenant,
                )
                for permission in permissions
            ]

            Access.objects.bulk_create(access_list)

            if attribute_filter:
                for access in access_list:
                    ResourceDefinition.objects.create(
                        attributeFilter=attribute_filter, access=access, tenant=role.tenant
                    )

        return role

    def new_group(self, name: str, users: list[str], tenant: Tenant) -> Group:
        """Create a new group with the given name, users, and tenant."""
        group = Group.objects.create(name=name, tenant=tenant)

        principals = [Principal.objects.get_or_create(username=username, tenant=tenant)[0] for username in users]

        group.principals.add(*principals)

        return group

    def add_role_to_group(self, role: Role, group: Group, tenant: Tenant) -> Policy:
        """Add a role to a group for a given tenant and return the policy."""
        policy, _ = Policy.objects.get_or_create(name=f"System Policy_{group.name}", group=group, tenant=tenant)
        policy.roles.add(role)
        policy.save()
        return policy