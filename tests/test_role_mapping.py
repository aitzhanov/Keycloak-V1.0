# Copyright 2026 Президентский центр Республики Казахстан
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

from odoo.tests import tagged

from .common import KeycloakCase


@tagged("post_install", "-at_install")
class TestRoleMapping(KeycloakCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.group_a = cls.env["res.groups"].create({"name": "KC Group A"})
        cls.group_b = cls.env["res.groups"].create({"name": "KC Group B"})
        cls.env["auth.keycloak.role.mapping"].create(
            [
                {
                    "provider_id": cls.provider.id,
                    "keycloak_role": "role_a",
                    "group_id": cls.group_a.id,
                },
                {
                    "provider_id": cls.provider.id,
                    "keycloak_role": "role_b",
                    "group_id": cls.group_b.id,
                },
            ]
        )
        cls.user = cls.env["res.users"].create(
            {
                "name": "KC User",
                "login": "kc_user@example.kz",
                "oauth_provider_id": cls.provider.id,
                "oauth_uid": "sub-123",
            }
        )

    def test_extract_realm_roles(self):
        roles = self.provider._keycloak_extract_roles(
            {"realm_access": {"roles": ["role_a", "offline_access"]}}, {}
        )
        self.assertIn("role_a", roles)
        self.assertIn("offline_access", roles)

    def test_extract_client_roles_qualified(self):
        roles = self.provider._keycloak_extract_roles(
            {"resource_access": {"odoo-portal": {"roles": ["admin"]}}}, {}
        )
        self.assertIn("admin", roles)
        self.assertIn("odoo-portal:admin", roles)

    def test_reconcile_adds_then_swaps_groups(self):
        # role_a present -> group_a granted, group_b not.
        self.user._keycloak_reconcile_groups(
            self.provider, {"realm_access": {"roles": ["role_a"]}}, {}
        )
        self.assertIn(self.group_a, self.user.group_ids)
        self.assertNotIn(self.group_b, self.user.group_ids)

        # now only role_b -> group_a removed, group_b granted (reconciliation).
        self.user._keycloak_reconcile_groups(
            self.provider, {"realm_access": {"roles": ["role_b"]}}, {}
        )
        self.assertNotIn(self.group_a, self.user.group_ids)
        self.assertIn(self.group_b, self.user.group_ids)
