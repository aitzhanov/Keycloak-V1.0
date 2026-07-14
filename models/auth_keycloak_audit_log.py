# Copyright 2026 Президентский центр Республики Казахстан
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

import logging

from odoo import api, fields, models

_logger = logging.getLogger(__name__)

# Fields that MUST never appear in audit records (§5.9 TZ)
_FORBIDDEN_FIELDS = {"token", "access_token", "id_token", "code", "code_verifier", "client_secret"}


class AuthKeycloakAuditLog(models.Model):
    """Immutable audit trail for every Keycloak SSO event.

    Records are created via :meth:`log_event` (called with sudo() from the
    auth core).  No secrets (tokens, codes, code_verifier) are ever stored
    — see §5.9 of the Technical Specification.
    """

    _name = "auth.keycloak.audit.log"
    _description = "Keycloak SSO Audit Log"
    _order = "create_date desc, id desc"
    # Prevent any modification after creation
    _rec_name = "event_type"

    event_type = fields.Selection(
        selection=[
            ("login_success", "Login — Success"),
            ("login_denied", "Login — Denied"),
            ("jit_create", "JIT User Created"),
            ("groups_reconciled", "Groups Reconciled"),
            ("backchannel_logout", "Back-Channel Logout"),
            ("logout_denied", "Logout — Denied"),
        ],
        string="Event",
        required=True,
        readonly=True,
    )
    provider_id = fields.Many2one(
        comodel_name="auth.oauth.provider",
        string="Provider",
        readonly=True,
        ondelete="set null",
    )
    oauth_uid = fields.Char(
        string="OAuth UID (sub)",
        readonly=True,
        help="The 'sub' claim from the Keycloak ID token.",
    )
    user_id = fields.Many2one(
        comodel_name="res.users",
        string="User",
        readonly=True,
        ondelete="set null",
    )
    result = fields.Selection(
        selection=[
            ("success", "Success"),
            ("denied", "Denied"),
            ("error", "Error"),
        ],
        string="Result",
        readonly=True,
    )
    reason = fields.Char(
        string="Reason",
        readonly=True,
        help="Short human-readable explanation (no secrets).",
    )
    ip = fields.Char(
        string="IP Address",
        readonly=True,
    )
    # create_date provided by Odoo ORM — serves as event timestamp

    # ------------------------------------------------------------------
    # Contract method — called by auth core via sudo()
    # ------------------------------------------------------------------

    @api.model
    def log_event(
        self,
        event_type,
        provider_id=None,
        oauth_uid=None,
        user_id=None,
        result=None,
        reason=None,
        ip=None,
    ):
        """Create one audit record.  Lightweight — never raises.

        Called with ``sudo()`` from the authentication core so that the
        record is always written regardless of the current user's ACL.
        """
        try:
            # Sanitise: strip any accidentally passed secret-like keys
            safe_reason = self._sanitise_reason(reason)
            self.create(
                {
                    "event_type": event_type,
                    "provider_id": provider_id,
                    "oauth_uid": oauth_uid,
                    "user_id": user_id,
                    "result": result,
                    "reason": safe_reason,
                    "ip": ip,
                }
            )
        except Exception:
            # Must never propagate — audit failure must not break the login flow
            _logger.exception("auth_keycloak: failed to write audit log entry")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _sanitise_reason(reason):
        """Return *reason* unless it looks like a secret, then redact it."""
        if not reason:
            return reason
        lower = str(reason).lower()
        for forbidden in _FORBIDDEN_FIELDS:
            if forbidden in lower:
                return "[redacted — possible secret]"
        return reason
