# Copyright 2026 Президентский центр Республики Казахстан
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

from odoo.exceptions import AccessDenied
from odoo.tests import tagged

from .common import KeycloakCase


@tagged("post_install", "-at_install")
class TestJit(KeycloakCase):
    def test_email_not_verified_is_denied(self):
        with self.assertRaises(AccessDenied):
            self.env["res.users"]._keycloak_check_email_verified(
                self.provider, {"sub": "s1", "email_verified": False}
            )

    def test_email_verified_passes(self):
        # Must not raise.
        self.env["res.users"]._keycloak_check_email_verified(
            self.provider, {"sub": "s1", "email_verified": True}
        )

    def test_missing_email_verified_denied_when_enforced(self):
        with self.assertRaises(AccessDenied):
            self.env["res.users"]._keycloak_check_email_verified(
                self.provider, {"sub": "s1"}
            )

    def test_signup_values_name_from_given_family(self):
        values = self.env["res.users"]._generate_signup_values(
            self.provider.id,
            {
                "user_id": "sub-9",
                "email": "ivan@example.kz",
                "given_name": "Ivan",
                "family_name": "Petrov",
            },
            {"access_token": "tok"},
        )
        self.assertEqual(values["name"], "Ivan Petrov")
        self.assertEqual(values["login"], "ivan@example.kz")
