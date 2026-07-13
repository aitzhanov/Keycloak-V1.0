# Copyright 2026 Президентский центр Республики Казахстан
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

import logging

import requests

from odoo import _, api, fields, models
from odoo.exceptions import UserError
from odoo.http import request

try:
    from jose import jwt
except ImportError:
    jwt = None

_logger = logging.getLogger(__name__)

# Endpoints and keys are always read from the realm discovery document
# (ТЗ §4.2): hardcoding endpoints is forbidden.
DISCOVERY_SUFFIX = "/.well-known/openid-configuration"

# OIDC Back-Channel Logout event identifier (spec §2.4).
BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


class AuthOauthProvider(models.Model):
    _inherit = "auth.oauth.provider"

    is_keycloak = fields.Boolean(
        string="Keycloak provider",
        help="Enable the ЦПФ Keycloak specifics (role mapping, JIT rules, "
        "email_verified enforcement, single logout) for this provider.",
    )
    keycloak_server_url = fields.Char(
        string="Keycloak base URL",
        help="Base URL of the Keycloak server. Include the '/auth' segment for "
        "legacy (pre-17) Keycloak, e.g. https://sso.example.kz/auth. "
        "Modern Keycloak: https://sso.example.kz",
    )
    keycloak_realm = fields.Char(
        string="Realm",
        help="Keycloak realm name (isolated user/role/client space).",
    )
    keycloak_discovery_url = fields.Char(
        string="Discovery URL",
        compute="_compute_keycloak_discovery_url",
        help="OpenID Connect discovery document derived from base URL + realm.",
    )
    keycloak_issuer = fields.Char(
        string="Issuer",
        compute="_compute_keycloak_issuer",
        help="Expected token issuer (base URL + realm), used to validate tokens.",
    )
    use_pkce = fields.Boolean(
        string="Use PKCE (S256)",
        default=True,
        help="Authorization Code Flow with PKCE (S256). Provided by auth_oidc "
        "for the OpenID Connect authorization code flow.",
    )
    enforce_email_verified = fields.Boolean(
        string="Require verified e-mail",
        default=True,
        help="Refuse login / provisioning unless the token carries "
        "email_verified=true (ТЗ §5.5, §6.2).",
    )
    enable_backchannel_logout = fields.Boolean(
        string="Accept back-channel logout",
        default=False,
        help="Accept OIDC Back-Channel Logout Tokens from Keycloak to end "
        "Odoo sessions when the SSO session ends (ТЗ §4.4).",
    )
    keycloak_end_session_endpoint = fields.Char(
        string="End session URL",
        help="RP-initiated logout endpoint (end_session_endpoint), populated "
        "from discovery by Test Connection.",
    )
    role_mapping_ids = fields.One2many(
        "auth.keycloak.role.mapping",
        "provider_id",
        string="Role mapping",
        help="Keycloak role -> Odoo group rules, reconciled on every login.",
    )

    @api.depends("keycloak_server_url", "keycloak_realm")
    def _compute_keycloak_discovery_url(self):
        for provider in self:
            base = (provider.keycloak_server_url or "").rstrip("/")
            realm = (provider.keycloak_realm or "").strip("/")
            if base and realm:
                provider.keycloak_discovery_url = (
                    f"{base}/realms/{realm}{DISCOVERY_SUFFIX}"
                )
            else:
                provider.keycloak_discovery_url = False

    @api.depends("keycloak_server_url", "keycloak_realm")
    def _compute_keycloak_issuer(self):
        for provider in self:
            base = (provider.keycloak_server_url or "").rstrip("/")
            realm = (provider.keycloak_realm or "").strip("/")
            provider.keycloak_issuer = f"{base}/realms/{realm}" if base and realm else False

    # ---- role extraction ---------------------------------------------------

    def _keycloak_extract_roles(self, validation, params=None):
        """Collect Keycloak roles from the available claims.

        Keycloak usually places realm_access.roles / resource_access in the
        ACCESS token rather than the id_token, so we look at both. The access
        token is fetched server-to-server over TLS in the authorization code
        flow (back-channel), so reading its claims without re-verifying the
        signature is acceptable here; the id_token signature is already
        verified by auth_oidc.
        """
        self.ensure_one()
        roles = set()

        def collect(claims):
            if not isinstance(claims, dict):
                return
            for role in (claims.get("realm_access") or {}).get("roles", []) or []:
                roles.add(role)
            for client, data in (claims.get("resource_access") or {}).items():
                for role in (data or {}).get("roles", []) or []:
                    roles.add(role)  # bare role name
                    roles.add(f"{client}:{role}")  # client-qualified form

        collect(validation)
        access_token = (params or {}).get("access_token")
        if access_token and jwt is not None:
            try:
                collect(jwt.get_unverified_claims(access_token))
            except Exception:  # noqa: BLE001 - token may be opaque
                _logger.debug("Could not decode access_token for role extraction")
        return roles

    # ---- Back-Channel Logout token validation ------------------------------

    def _keycloak_decode_logout_token(self, logout_token):
        """Verify the signature of a Back-Channel Logout Token via JWKS.

        Reuses auth_oidc's _get_keys (JWKS fetch + cache). Raises if the token
        is not signed by this realm. Returns the decoded claims.
        """
        self.ensure_one()
        if jwt is None:
            raise UserError(_("python-jose is not installed."))
        header = jwt.get_unverified_header(logout_token)
        keys = self._get_keys(header.get("kid"))
        last_error = None
        for key in keys:
            try:
                return jwt.decode(
                    logout_token,
                    key,
                    algorithms=["RS256"],
                    audience=self.client_id,
                    options={"verify_at_hash": False},
                )
            except Exception as exc:  # noqa: BLE001 - try the next key
                last_error = exc
        raise last_error or ValueError("No usable signing key for logout token")

    def _keycloak_check_logout_claims(self, claims):
        """Validate Back-Channel Logout Token claims (OIDC BCL spec §2.4).

        Signature/aud are already checked by _keycloak_decode_logout_token;
        this covers the logout-specific claim rules and is pure/unit-testable.
        Returns a list of error strings (empty = valid).
        """
        self.ensure_one()
        errors = []
        if self.keycloak_issuer and claims.get("iss") != self.keycloak_issuer:
            errors.append("iss mismatch")
        events = claims.get("events") or {}
        if not isinstance(events, dict) or BACKCHANNEL_LOGOUT_EVENT not in events:
            errors.append("missing backchannel-logout event")
        if not claims.get("sub") and not claims.get("sid"):
            errors.append("neither sub nor sid present")
        if "nonce" in claims:
            # A logout token MUST NOT contain a nonce (spec §2.4).
            errors.append("nonce must not be present")
        return errors

    # ---- Test Connection ---------------------------------------------------

    def action_keycloak_test_connection(self):
        """Fetch the realm discovery document + JWKS and report the result.

        Also populates the endpoint fields (auth/token/jwks/end_session) so the
        provider is configured from discovery, not by hand (ТЗ §5.8).
        """
        self.ensure_one()
        url = self.keycloak_discovery_url
        if not url:
            return self._keycloak_notify(
                _("Set the Keycloak base URL and realm first."), success=False
            )
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            disc = resp.json()
        except Exception as exc:  # noqa: BLE001
            return self._keycloak_notify(
                _("Discovery request failed: %s") % exc, success=False
            )

        vals = {}
        if disc.get("authorization_endpoint"):
            vals["auth_endpoint"] = disc["authorization_endpoint"]
        if disc.get("token_endpoint"):
            vals["token_endpoint"] = disc["token_endpoint"]
        if disc.get("jwks_uri"):
            vals["jwks_uri"] = disc["jwks_uri"]
        if disc.get("userinfo_endpoint"):
            vals["validation_endpoint"] = disc["userinfo_endpoint"]
        vals["keycloak_end_session_endpoint"] = disc.get("end_session_endpoint") or False
        self.write(vals)

        # Verify the JWKS is reachable and has keys.
        key_count = None
        if disc.get("jwks_uri"):
            try:
                jresp = requests.get(disc["jwks_uri"], timeout=10)
                jresp.raise_for_status()
                key_count = len(jresp.json().get("keys", []))
            except Exception:  # noqa: BLE001
                key_count = None

        has_logout = bool(disc.get("end_session_endpoint"))
        msg = _(
            "Connected to realm '%(realm)s'.\n"
            "Issuer: %(iss)s\n"
            "JWKS keys: %(keys)s\n"
            "Single Logout endpoint: %(logout)s\n"
            "Endpoints saved on the provider."
        ) % {
            "realm": self.keycloak_realm,
            "iss": disc.get("issuer", "?"),
            "keys": key_count if key_count is not None else _("unavailable"),
            "logout": _("present") if has_logout else _("NOT advertised"),
        }
        return self._keycloak_notify(msg, success=True)

    # ---- audit contract (implemented by auth.keycloak.audit.log, Поток 2) --

    def _keycloak_audit(
        self, event_type, oauth_uid=None, user=None, result=None, reason=None
    ):
        """Safe audit hook. No-ops until the audit model is installed.

        Contract for Поток 2: auth.keycloak.audit.log must expose
        log_event(event_type, provider_id, oauth_uid, user_id, result, reason, ip).
        Never let auditing break authentication.
        """
        self.ensure_one()
        if "auth.keycloak.audit.log" not in self.env:
            return
        try:
            self.env["auth.keycloak.audit.log"].sudo().log_event(
                event_type=event_type,
                provider_id=self.id,
                oauth_uid=oauth_uid,
                user_id=user.id if user else False,
                result=result,
                reason=reason,
                ip=self._keycloak_client_ip(),
            )
        except Exception:  # noqa: BLE001 - auditing must never block login
            _logger.exception("Keycloak audit logging failed (non-fatal)")

    def _keycloak_client_ip(self):
        try:
            return request.httprequest.remote_addr if request else False
        except Exception:  # noqa: BLE001
            return False

    def _keycloak_notify(self, message, success=True):
        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {
                "title": _("Keycloak") if success else _("Keycloak — error"),
                "message": message,
                "type": "success" if success else "danger",
                "sticky": not success,
            },
        }
