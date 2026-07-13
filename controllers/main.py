# Copyright 2026 Президентский центр Республики Казахстан
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

import logging

from werkzeug.urls import url_encode

from odoo import http
from odoo.http import request
from odoo.addons.web.controllers.session import Session

_logger = logging.getLogger(__name__)


class KeycloakSession(Session):
    """RP-initiated Single Logout (ТЗ §4.4)."""

    @http.route()
    def logout(self, redirect="/odoo"):
        # Capture the Keycloak logout target BEFORE the Odoo session is cleared.
        end_session_url = None
        user = request.env.user
        provider = user.sudo().oauth_provider_id if user and user.id else None
        if provider and provider.is_keycloak and provider.keycloak_end_session_endpoint:
            post_logout = request.httprequest.url_root.rstrip("/") + (redirect or "/")
            query = url_encode(
                {
                    "client_id": provider.client_id,
                    "post_logout_redirect_uri": post_logout,
                }
            )
            end_session_url = f"{provider.keycloak_end_session_endpoint}?{query}"

        response = super().logout(redirect=redirect)

        # Bounce to Keycloak so the SSO session ends for every application.
        if end_session_url:
            return request.redirect(end_session_url, 303)
        return response


class KeycloakBackchannel(http.Controller):
    """OIDC Back-Channel Logout receiver (ТЗ §4.4, §5.6)."""

    @http.route(
        "/auth_keycloak/backchannel_logout",
        type="http",
        auth="none",
        methods=["POST"],
        csrf=False,
        save_session=False,
    )
    def backchannel_logout(self, logout_token=None, **kwargs):
        if not logout_token:
            return request.make_response("missing logout_token", status=400)

        providers = (
            request.env["auth.oauth.provider"]
            .sudo()
            .search(
                [
                    ("is_keycloak", "=", True),
                    ("enable_backchannel_logout", "=", True),
                ]
            )
        )
        for provider in providers:
            try:
                claims = provider._keycloak_decode_logout_token(logout_token)
            except Exception:  # noqa: BLE001 - not signed by this realm, try next
                continue
            errors = provider._keycloak_check_logout_claims(claims)
            if errors:
                _logger.warning("Rejected Keycloak logout token: %s", errors)
                provider._keycloak_audit(
                    "logout_denied", result="denied", reason=",".join(errors)
                )
                return request.make_response("invalid logout token", status=400)

            users = request.env["res.users"]._keycloak_backchannel_logout(
                provider, sub=claims.get("sub"), sid=claims.get("sid")
            )
            provider._keycloak_audit(
                "backchannel_logout",
                oauth_uid=claims.get("sub"),
                user=users[:1] if users else None,
                result="success",
            )
            return request.make_response("", status=200)

        return request.make_response("no matching provider", status=400)
