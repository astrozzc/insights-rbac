#
# Copyright 2025 Red Hat, Inc.
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
"""Test the cleanup_orphaned_kessel_relationships unified internal endpoint."""
import json
from unittest.mock import MagicMock, patch

from django.test import override_settings
from rest_framework import status
from rest_framework.test import APIClient

from api.models import User
from management.models import Group
from management.role.model import Role
from migration_tool.in_memory_tuples import (
    all_of,
    relation,
    resource_type,
    subject,
)
from tests.identity_request import IdentityRequest
from tests.management.role.test_dual_write import DualWriteGroupTestCase


ENDPOINT_URL = "/_private/api/utils/cleanup_orphaned_kessel_relationships/"


@override_settings(REPLICATION_TO_RELATION_ENABLED=True)
class CleanupOrphanedKesselRelationshipsTest(DualWriteGroupTestCase, IdentityRequest):
    """Test the cleanup_orphaned_kessel_relationships unified endpoint."""

    def setUp(self):
        """Set up the test."""
        DualWriteGroupTestCase.setUp(self)
        IdentityRequest.setUp(self)
        self.client = APIClient()
        self.internal_request_context = self._create_request_context(
            self.customer_data, self.user_data, is_internal=True
        )
        self.request = self.internal_request_context["request"]
        user = User()
        user.username = self.user_data["username"]
        user.account = self.customer_data["account_id"]
        self.request.user = user

    # =========================================================================
    # Input Validation Tests
    # =========================================================================

    def test_endpoint_requires_at_least_one_identifier(self):
        """Test that the endpoint requires at least one of group_uuid, role_uuid, or role_name."""
        response = self.client.post(
            ENDPOINT_URL,
            data=json.dumps({}),
            content_type="application/json",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("At least one of", response.json().get("detail", ""))

    # =========================================================================
    # Group-only Scenario Tests
    # =========================================================================

    def test_group_only_returns_error_if_group_exists(self):
        """Test that group-only cleanup returns error if the group still exists."""
        group, _ = self.given_group("test-group", ["u1"])
        response = self.client.post(
            ENDPOINT_URL,
            data=json.dumps({"group_uuid": str(group.uuid)}),
            content_type="application/json",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_json = response.json()
        self.assertTrue(response_json.get("group_exists"))
        self.assertIn("still exists", response_json.get("detail", ""))

    @patch("internal.views.create_client_channel")
    @patch("internal.views.jwt_manager.get_jwt_from_redis")
    def test_group_only_dry_run_does_not_delete(self, mock_jwt, mock_channel):
        """Test that group-only cleanup with replicate_removal=false doesn't delete."""
        mock_jwt.return_value = "test-token"
        role = self.given_v1_role("dry-run-role", default=["app1:hosts:read"])
        group, _ = self.given_group("dry-run-group", [])
        group_uuid = str(group.uuid)
        self.given_roles_assigned_to_group(group, roles=[role])

        initial_subject_tuples = self.tuples.find_tuples(
            all_of(
                resource_type("rbac", "role_binding"),
                relation("subject"),
                subject("rbac", "group", group_uuid, "member"),
            )
        )
        initial_count = len(initial_subject_tuples)

        # Delete group directly (bypass dual write)
        Group.objects.filter(uuid=group_uuid).delete()

        mock_stub = MagicMock()
        mock_channel_instance = MagicMock()
        mock_channel.return_value.__enter__ = MagicMock(return_value=mock_channel_instance)
        mock_channel.return_value.__exit__ = MagicMock(return_value=False)
        mock_stub.ReadTuples = MagicMock(return_value=iter([]))

        with patch(
            "kessel.relations.v1beta1.relation_tuples_pb2_grpc.KesselTupleServiceStub",
            return_value=mock_stub,
        ):
            response = self.client.post(
                ENDPOINT_URL,
                data=json.dumps({"group_uuid": group_uuid, "replicate_removal": False}),
                content_type="application/json",
                **self.request.META,
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_json = response.json()
        self.assertFalse(response_json["replicated"])
        self.assertFalse(response_json["group_exists"])

        # Verify tuples still exist in in-memory store
        remaining_tuples = self.tuples.find_tuples(
            all_of(
                resource_type("rbac", "role_binding"),
                relation("subject"),
                subject("rbac", "group", group_uuid, "member"),
            )
        )
        self.assertEqual(len(remaining_tuples), initial_count)

    # =========================================================================
    # Role-only Scenario Tests
    # =========================================================================

    def test_role_only_returns_error_if_role_exists(self):
        """Test that role-only cleanup returns error if the role still exists."""
        role = self.given_v1_role("test-role", default=["app1:hosts:read"])
        response = self.client.post(
            ENDPOINT_URL,
            data=json.dumps({"role_uuid": str(role.uuid)}),
            content_type="application/json",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_json = response.json()
        self.assertTrue(response_json.get("role_exists"))
        self.assertIn("still exists", response_json.get("detail", ""))

    @patch("internal.views.create_client_channel")
    @patch("internal.views.jwt_manager.get_jwt_from_redis")
    def test_role_only_dry_run_does_not_delete(self, mock_jwt, mock_channel):
        """Test that role-only cleanup with replicate_removal=false doesn't delete."""
        mock_jwt.return_value = "test-token"
        role = self.given_v1_role("dry-run-role", default=["app1:hosts:read"])
        group, _ = self.given_group("dry-run-group", [])
        role_uuid = str(role.uuid)
        self.given_roles_assigned_to_group(group, roles=[role])

        initial_role_tuples = self.tuples.find_tuples(
            all_of(
                resource_type("rbac", "role_binding"),
                relation("role"),
                subject("rbac", "role", role_uuid),
            )
        )
        initial_count = len(initial_role_tuples)

        # Delete role directly (bypass dual write)
        Role.objects.filter(uuid=role_uuid).delete()

        mock_stub = MagicMock()
        mock_channel_instance = MagicMock()
        mock_channel.return_value.__enter__ = MagicMock(return_value=mock_channel_instance)
        mock_channel.return_value.__exit__ = MagicMock(return_value=False)
        mock_stub.ReadTuples = MagicMock(return_value=iter([]))

        with patch(
            "kessel.relations.v1beta1.relation_tuples_pb2_grpc.KesselTupleServiceStub",
            return_value=mock_stub,
        ):
            response = self.client.post(
                ENDPOINT_URL,
                data=json.dumps({"role_uuid": role_uuid, "replicate_removal": False}),
                content_type="application/json",
                **self.request.META,
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_json = response.json()
        self.assertFalse(response_json["replicated"])
        self.assertFalse(response_json["role_exists"])

        # Verify tuples still exist in in-memory store
        remaining_tuples = self.tuples.find_tuples(
            all_of(
                resource_type("rbac", "role_binding"),
                relation("role"),
                subject("rbac", "role", role_uuid),
            )
        )
        self.assertEqual(len(remaining_tuples), initial_count)

    # =========================================================================
    # Group + Role Scenario Tests
    # =========================================================================

    @patch("internal.views.create_client_channel")
    @patch("internal.views.jwt_manager.get_jwt_from_redis")
    def test_group_and_role_with_nonexistent_role_by_name(self, mock_jwt, mock_channel):
        """Test cleanup when both group and role_name provided but role doesn't exist."""
        mock_jwt.return_value = "test-token"
        role = self.given_v1_role("orphan-role", default=["app1:hosts:read"])
        group, _ = self.given_group("orphan-group", [])
        group_uuid = str(group.uuid)
        role_name = role.name
        self.given_roles_assigned_to_group(group, roles=[role])

        # Delete role directly (bypass dual write)
        Role.objects.filter(name=role_name).delete()

        # Delete group directly
        Group.objects.filter(uuid=group_uuid).delete()

        mock_stub = MagicMock()
        mock_channel_instance = MagicMock()
        mock_channel.return_value.__enter__ = MagicMock(return_value=mock_channel_instance)
        mock_channel.return_value.__exit__ = MagicMock(return_value=False)
        mock_stub.ReadTuples = MagicMock(return_value=iter([]))

        with patch(
            "kessel.relations.v1beta1.relation_tuples_pb2_grpc.KesselTupleServiceStub",
            return_value=mock_stub,
        ):
            response = self.client.post(
                ENDPOINT_URL,
                data=json.dumps({"group_uuid": group_uuid, "role_name": role_name, "replicate_removal": False}),
                content_type="application/json",
                **self.request.META,
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_json = response.json()
        self.assertFalse(response_json["replicated"])
        self.assertFalse(response_json["group_exists"])
        # role_exists should be None since we looked up by name and it doesn't exist
        self.assertIsNone(response_json.get("role_exists"))

    @patch("internal.views.create_client_channel")
    @patch("internal.views.jwt_manager.get_jwt_from_redis")
    def test_group_and_role_resolves_role_by_name(self, mock_jwt, mock_channel):
        """Test that role_name is resolved to role_uuid when role exists."""
        mock_jwt.return_value = "test-token"
        role = self.given_v1_role("existing-role", default=["app1:hosts:read"])
        group, _ = self.given_group("test-group", [])
        group_uuid = str(group.uuid)
        role_uuid = str(role.uuid)
        self.given_roles_assigned_to_group(group, roles=[role])

        # Delete group directly (role still exists)
        Group.objects.filter(uuid=group_uuid).delete()

        mock_stub = MagicMock()
        mock_channel_instance = MagicMock()
        mock_channel.return_value.__enter__ = MagicMock(return_value=mock_channel_instance)
        mock_channel.return_value.__exit__ = MagicMock(return_value=False)
        mock_stub.ReadTuples = MagicMock(return_value=iter([]))

        with patch(
            "kessel.relations.v1beta1.relation_tuples_pb2_grpc.KesselTupleServiceStub",
            return_value=mock_stub,
        ):
            response = self.client.post(
                ENDPOINT_URL,
                data=json.dumps({"group_uuid": group_uuid, "role_name": role.name, "replicate_removal": False}),
                content_type="application/json",
                **self.request.META,
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_json = response.json()
        # role_uuid should be resolved
        self.assertEqual(response_json["role_uuid"], role_uuid)
        self.assertTrue(response_json["role_exists"])
        self.assertFalse(response_json["group_exists"])
