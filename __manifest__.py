# Copyright 2026 Президентский центр Республики Казахстан
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)
{
    "name": "Authentication — Keycloak (SSO for ЦПФ)",
    "summary": "Keycloak SSO layer over OCA auth_oidc: role mapping, JIT, "
    "email_verified enforcement, single logout, audit.",
    "version": "19.0.1.0.0",
    "category": "Tools",
    "author": "Президентский центр Республики Казахстан",
    "website": "https://github.com/",
    "license": "AGPL-3",
    # Thin, portable layer on top of the standard Odoo OAuth stack + OCA OIDC.
    "depends": ["base", "auth_oauth", "auth_oidc"],
    # python-jose is inherited from auth_oidc (JWT/JWKS handling).
    "external_dependencies": {"python": ["python-jose"]},
    "data": [
        "security/ir.model.access.csv",
        "views/auth_oauth_provider_views.xml",
        "views/auth_keycloak_menus.xml",
        # NOTE (integration): data/auth_keycloak_provider_data.xml is intentionally
        # NOT loaded — it hardcodes a specific environment (fictional cpf-external
        # realm) which breaks portability (ТЗ §7.4) and currently has invalid
        # fields. Kept as a reference stub; see docs/provider_president_center.
        # example.xml for a correct, real-realm example. Translations (i18n/*.po)
        # are auto-loaded by Odoo per installed language — not listed here.
    ],
    "installable": True,
    "application": False,
}
