# Copyright 2026 Президентский центр Республики Казахстан
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

from odoo.tests import TransactionCase


class KeycloakCase(TransactionCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.provider = cls.env["auth.oauth.provider"].create(
            {
                "name": "Keycloak test",
                "body": "Log in with Keycloak",
                "client_id": "odoo-portal",
                "flow": "id_token_code",
                # auth_endpoint is required by core auth_oauth; in real use it
                # is filled by "Test Connection" from the discovery document.
                "auth_endpoint": "https://sso.example.kz/auth/realms/"
                "cpf-external/protocol/openid-connect/auth",
                "token_endpoint": "https://sso.example.kz/auth/realms/"
                "cpf-external/protocol/openid-connect/token",
                "jwks_uri": "https://sso.example.kz/auth/realms/"
                "cpf-external/protocol/openid-connect/certs",
                "is_keycloak": True,
                "keycloak_server_url": "https://sso.example.kz/auth",
                "keycloak_realm": "cpf-external",
                "enforce_email_verified": True,
                "enable_backchannel_logout": True,
            }
        )
