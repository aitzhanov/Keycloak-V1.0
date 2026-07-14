# Copyright 2026 Президентский центр Республики Казахстан
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

from odoo import fields, models


class AuthKeycloakRoleMapping(models.Model):
    """Data-driven mapping: a Keycloak role -> an Odoo group.

    Rows are edited by the administrator (not code) and reconciled on every
    login, so access rights stay in sync with Keycloak (ТЗ §5.4).
    """

    _name = "auth.keycloak.role.mapping"
    _description = "Keycloak Role -> Odoo Group mapping"
    _order = "provider_id, keycloak_role"

    provider_id = fields.Many2one(
        "auth.oauth.provider",
        string="Provider",
        required=True,
        ondelete="cascade",
        index=True,
    )
    keycloak_role = fields.Char(
        string="Keycloak role",
        required=True,
        help="Role name as it appears in the token. Either a realm role "
        "(realm_access.roles, e.g. 'cpf_admin') or a client role which may "
        "also be matched in the '<client_id>:<role>' form (resource_access).",
    )
    group_id = fields.Many2one(
        "res.groups",
        string="Odoo group",
        required=True,
        ondelete="cascade",
        help="Group granted to the user while the Keycloak role is present, "
        "and removed when it is not.",
    )
    enabled = fields.Boolean(
        default=True,
        help="Disable to stop this rule from being applied at login without "
        "deleting it. (Not the magic 'active' field, so the row stays visible.)",
    )

    _sql_constraints = [
        (
            "role_group_uniq",
            "unique(provider_id, keycloak_role, group_id)",
            "This Keycloak role is already mapped to this group for the provider.",
        ),
    ]
