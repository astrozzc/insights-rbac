"""Tests for merging duplicate principals during user_id assignment."""

from unittest.mock import patch

from django.db import IntegrityError
from django.test import override_settings

from api.models import Tenant, User
from management.group.model import Group
from management.principal.model import Principal
from management.role_binding.model import RoleBinding, RoleBindingPrincipal
from management.role.v2_model import CustomRoleV2
from management.tenant_service.tenant_service import (
    _ensure_principal_with_user_id_in_tenant,
    merge_obsolete_principal_into_survivor,
)
from migration_tool.in_memory_tuples import (
    InMemoryRelationReplicator,
    InMemoryTuples,
    all_of,
    relation,
    resource,
    subject,
)
from tests.identity_request import IdentityRequest
from tests.v2_util import bootstrap_tenant_for_v2_test


class _ReplicationTracker:
    """Records replication add/remove lists for assertions."""

    def __init__(self):
        self.tuples_added = []
        self.tuples_removed = []

    def replicate(self, event):
        self.tuples_added.extend(event.add)
        self.tuples_removed.extend(event.remove)


@override_settings(ATOMIC_RETRY_DISABLED=True)
class MergePrincipalTests(IdentityRequest):
    """Tests for obsolete-into-survivor principal merge."""

    def setUp(self):
        super().setUp()
        bootstrap_tenant_for_v2_test(self.tenant)

    def test_merge_keeps_survivor_group_membership_and_assigns_user_id(self):
        """Survivor (no user_id) keeps its groups and receives user_id; obsolete is deleted."""
        obsolete = Principal.objects.create(username="jaross@redhat.com", tenant=self.tenant, user_id="54181241")
        survivor = Principal.objects.create(username="jdross@redhat.com", tenant=self.tenant)
        group = Group.objects.create(name="engineering", tenant=self.tenant)
        group.principals.add(survivor)

        tracker = _ReplicationTracker()
        result = merge_obsolete_principal_into_survivor(survivor, obsolete, user_id="54181241", replicator=tracker)
        self.assertIsNone(result)

        self.assertFalse(Principal.objects.filter(pk=obsolete.pk).exists())
        survivor.refresh_from_db()
        self.assertEqual(survivor.user_id, "54181241")
        self.assertEqual(list(group.principals.all()), [survivor])

    def test_merge_transfers_obsolete_groups_to_survivor(self):
        """Groups only the obsolete principal belonged to are added to the survivor."""
        obsolete = Principal.objects.create(username="jaross@redhat.com", tenant=self.tenant, user_id="54181241")
        survivor = Principal.objects.create(username="jdross@redhat.com", tenant=self.tenant)
        survivor_group = Group.objects.create(name="engineering", tenant=self.tenant)
        obsolete_group = Group.objects.create(name="legacy", tenant=self.tenant)
        survivor_group.principals.add(survivor)
        obsolete_group.principals.add(obsolete)

        tracker = _ReplicationTracker()
        result = merge_obsolete_principal_into_survivor(survivor, obsolete, user_id="54181241", replicator=tracker)
        self.assertIsNone(result)

        survivor.refresh_from_db()
        self.assertEqual(survivor.user_id, "54181241")
        self.assertCountEqual(survivor.group.values_list("name", flat=True), ["engineering", "legacy"])

    def test_merge_replicates_group_member_tuple_for_survivor(self):
        """V2 tenants replicate group membership tuples for the survivor after user_id assignment."""
        obsolete = Principal.objects.create(username="jaross@redhat.com", tenant=self.tenant, user_id="54181241")
        survivor = Principal.objects.create(username="jdross@redhat.com", tenant=self.tenant)
        group = Group.objects.create(name="engineering", tenant=self.tenant)
        group.principals.add(survivor)

        tuples = InMemoryTuples()
        replicator = InMemoryRelationReplicator(tuples)
        result = merge_obsolete_principal_into_survivor(survivor, obsolete, user_id="54181241", replicator=replicator)
        self.assertIsNone(result)

        self.assertEqual(
            tuples.count_tuples(
                all_of(
                    resource("rbac", "group", str(group.uuid)),
                    relation("member"),
                    subject("rbac", "principal", "redhat/54181241"),
                )
            ),
            1,
        )

    def test_merge_removes_obsolete_group_member_tuple(self):
        """SpiceDB tuples for the obsolete principal are removed from its former groups."""
        obsolete = Principal.objects.create(username="jaross@redhat.com", tenant=self.tenant, user_id="54181241")
        survivor = Principal.objects.create(username="jdross@redhat.com", tenant=self.tenant)
        obsolete_group = Group.objects.create(name="legacy", tenant=self.tenant)
        obsolete_group.principals.add(obsolete)

        tracker = _ReplicationTracker()
        result = merge_obsolete_principal_into_survivor(survivor, obsolete, user_id="54181241", replicator=tracker)
        self.assertIsNone(result)

        expected_removed = Group.relationship_to_user_id_for_group(str(obsolete_group.uuid), "54181241")
        survivor.refresh_from_db()
        expected_added = obsolete_group.relationship_to_principal(survivor)
        self.assertCountEqual(tracker.tuples_removed, [expected_removed])
        self.assertCountEqual(tracker.tuples_added, [expected_added])

    def test_merge_transfers_role_binding_entries(self):
        """Direct role-binding entries on the obsolete principal move to the survivor."""
        obsolete = Principal.objects.create(username="jaross@redhat.com", tenant=self.tenant, user_id="54181241")
        survivor = Principal.objects.create(username="jdross@redhat.com", tenant=self.tenant)
        role = CustomRoleV2.objects.create(name="merge-test-role", tenant=self.tenant)
        binding = RoleBinding.objects.create(
            role=role,
            resource_type="workspace",
            resource_id="00000000-0000-0000-0000-000000000001",
            tenant=self.tenant,
        )
        RoleBindingPrincipal.objects.create(binding=binding, principal=obsolete, source="direct")

        obsolete_id = obsolete.pk
        tracker = _ReplicationTracker()
        result = merge_obsolete_principal_into_survivor(survivor, obsolete, user_id="54181241", replicator=tracker)
        self.assertIsNone(result)

        survivor.refresh_from_db()
        self.assertEqual(survivor.user_id, "54181241")
        self.assertFalse(Principal.objects.filter(pk=obsolete_id).exists())
        self.assertFalse(RoleBindingPrincipal.objects.filter(principal_id=obsolete_id).exists())
        self.assertTrue(
            RoleBindingPrincipal.objects.filter(binding=binding, principal=survivor, source="direct").exists()
        )

    def test_merge_raises_on_cross_tenant(self):
        """Cross-tenant merge raises RuntimeError; both principals are left unchanged."""
        other_tenant = Tenant.objects.create(
            tenant_name="other-tenant",
            account_id="99999999",
            org_id="99999999",
            ready=True,
        )
        obsolete = Principal.objects.create(username="jaross@redhat.com", tenant=other_tenant, user_id="54181241")
        survivor = Principal.objects.create(username="jdross@redhat.com", tenant=self.tenant)
        other_group = Group.objects.create(name="other-org-group", tenant=other_tenant)
        other_group.principals.add(obsolete)

        tracker = _ReplicationTracker()
        with self.assertRaises(RuntimeError):
            merge_obsolete_principal_into_survivor(survivor, obsolete, user_id="54181241", replicator=tracker)

        self.assertTrue(Principal.objects.filter(pk=obsolete.pk).exists())
        survivor.refresh_from_db()
        self.assertIsNone(survivor.user_id)
        self.assertEqual(list(other_group.principals.all()), [obsolete])

    def test_ensure_principal_merges_on_user_id_conflict(self):
        """Assigning a taken user_id merges obsolete into the current username principal."""
        obsolete = Principal.objects.create(username="jaross@redhat.com", tenant=self.tenant, user_id="54181241")
        survivor = Principal.objects.create(username="jdross@redhat.com", tenant=self.tenant)
        group = Group.objects.create(name="engineering", tenant=self.tenant)
        group.principals.add(survivor)

        user = User()
        user.username = "jdross@redhat.com"
        user.user_id = "54181241"
        user.org_id = self.tenant.org_id

        tracker = _ReplicationTracker()
        result = _ensure_principal_with_user_id_in_tenant(user, self.tenant, replicator=tracker)
        self.assertIsNone(result)

        self.assertFalse(Principal.objects.filter(pk=obsolete.pk).exists())
        survivor.refresh_from_db()
        self.assertEqual(survivor.user_id, "54181241")
        self.assertEqual(list(group.principals.all()), [survivor])

    def test_ensure_principal_raises_on_user_id_mismatch(self):
        """A principal with a different non-empty user_id raises RuntimeError."""
        obsolete = Principal.objects.create(username="jaross@redhat.com", tenant=self.tenant, user_id="54181241")
        principal = Principal.objects.create(username="jdross@redhat.com", tenant=self.tenant, user_id="99999999")
        user = User()
        user.username = "jdross@redhat.com"
        user.user_id = "54181241"
        user.org_id = self.tenant.org_id

        tracker = _ReplicationTracker()
        with self.assertRaises(RuntimeError):
            _ensure_principal_with_user_id_in_tenant(user, self.tenant, replicator=tracker)

        principal.refresh_from_db()
        self.assertEqual(principal.user_id, "99999999")
        self.assertTrue(Principal.objects.filter(pk=obsolete.pk).exists())

    def test_ensure_principal_upsert_integrity_error_creates_survivor_when_missing(self):
        """upsert IntegrityError path creates survivor principal when insert fails on user_id uniqueness."""
        obsolete = Principal.objects.create(username="jaross@redhat.com", tenant=self.tenant, user_id="54181241")
        user = User()
        user.username = "jdross@redhat.com"
        user.user_id = "54181241"
        user.org_id = self.tenant.org_id

        original_get_or_create = Principal.objects.get_or_create
        call_count = {"n": 0}

        def flaky_get_or_create(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise IntegrityError(
                    'duplicate key value violates unique constraint "management_principal_user_id_key"'
                )
            return original_get_or_create(*args, **kwargs)

        tracker = _ReplicationTracker()
        with patch.object(Principal.objects, "get_or_create", side_effect=flaky_get_or_create):
            result = _ensure_principal_with_user_id_in_tenant(user, self.tenant, upsert=True, replicator=tracker)
        self.assertIsNone(result)

        self.assertTrue(Principal.objects.filter(username="jdross@redhat.com", tenant=self.tenant).exists())
        self.assertFalse(Principal.objects.filter(pk=obsolete.pk).exists())
        survivor = Principal.objects.get(username="jdross@redhat.com", tenant=self.tenant)
        self.assertEqual(survivor.user_id, "54181241")

    def test_ensure_principal_noop_when_principal_already_has_user_id(self):
        """No merge when the matched principal already has the expected user_id."""
        principal = Principal.objects.create(username="jaross@redhat.com", tenant=self.tenant, user_id="54181241")
        user = User()
        user.username = "jaross@redhat.com"
        user.user_id = "54181241"
        user.org_id = self.tenant.org_id

        tracker = _ReplicationTracker()
        result = _ensure_principal_with_user_id_in_tenant(user, self.tenant, replicator=tracker)
        self.assertIsNone(result)

        self.assertTrue(Principal.objects.filter(pk=principal.pk).exists())
        self.assertEqual(Principal.objects.count(), 1)

    def test_ensure_principal_noop_when_bop_user_id_is_int(self):
        """BOP may return user_id as int; it should match the string stored on Principal."""
        principal = Principal.objects.create(username="jrobbins@redhat.com", tenant=self.tenant, user_id="7919876")
        user = User()
        user.username = "jrobbins@redhat.com"
        user.user_id = 7919876
        user.org_id = self.tenant.org_id

        tracker = _ReplicationTracker()
        result = _ensure_principal_with_user_id_in_tenant(user, self.tenant, replicator=tracker)
        self.assertIsNone(result)

        principal.refresh_from_db()
        self.assertEqual(principal.user_id, "7919876")
        self.assertEqual(Principal.objects.count(), 1)
