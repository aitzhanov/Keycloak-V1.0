# Copyright 2026 Президентский центр Республики Казахстан
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

from odoo.tests import tagged

from ..models.auth_oauth_provider import BACKCHANNEL_LOGOUT_EVENT
from .common import KeycloakCase


@tagged("post_install", "-at_install")
class TestLogout(KeycloakCase):
    def test_issuer_computed(self):
        self.assertEqual(
            self.provider.keycloak_issuer,
            "https://sso.example.kz/auth/realms/cpf-external",
        )

    def test_valid_logout_claims(self):
        claims = {
            "iss": self.provider.keycloak_issuer,
            "sub": "s1",
            "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
        }
        self.assertEqual(self.provider._keycloak_check_logout_claims(claims), [])

    def test_reject_nonce_and_missing_event(self):
        claims = {
            "iss": self.provider.keycloak_issuer,
            "sub": "s1",
            "events": {},
            "nonce": "abc",
        }
        errors = self.provider._keycloak_check_logout_claims(claims)
        self.assertTrue(any("event" in e for e in errors))
        self.assertTrue(any("nonce" in e for e in errors))

    def test_reject_bad_issuer(self):
        claims = {
            "iss": "https://evil.example/realms/x",
            "sub": "s1",
            "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
        }
        errors = self.provider._keycloak_check_logout_claims(claims)
        self.assertTrue(any("iss" in e for e in errors))

    def test_backchannel_bumps_epoch_and_invalidates_session(self):
        user = self.env["res.users"].create(
            {
                "name": "Logout User",
                "login": "logout_user@example.kz",
                "oauth_provider_id": self.provider.id,
                "oauth_uid": "sub-logout",
            }
        )
        before = user.keycloak_logout_epoch
        self.env["res.users"]._keycloak_backchannel_logout(
            self.provider, sub="sub-logout"
        )
        user.invalidate_recordset(["keycloak_logout_epoch"])
        self.assertEqual(user.keycloak_logout_epoch, before + 1)

    def test_backchannel_actually_changes_session_token(self):
        # Prove the epoch bump really invalidates sessions: the computed
        # session token must differ before vs after the logout.
        user = self.env["res.users"].create(
            {
                "name": "Token User",
                "login": "token_user@example.kz",
                "oauth_provider_id": self.provider.id,
                "oauth_uid": "sub-token",
            }
        )
        sid = "dummy-session-id"
        self.env.flush_all()
        token_before = user._compute_session_token(sid)

        self.env["res.users"]._keycloak_backchannel_logout(
            self.provider, sub="sub-token"
        )
        self.env.flush_all()
        user.invalidate_recordset()
        token_after = user._compute_session_token(sid)

        self.assertNotEqual(token_before, token_after)
