# Copyright 2026 Президентский центр Республики Казахстан
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

import logging

from odoo import Command, _, api, fields, models
from odoo.exceptions import AccessDenied, ValidationError
from odoo.http import request

_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = "res.users"

    keycloak_logout_epoch = fields.Integer(
        default=0,
        copy=False,
        help="Bumped on Keycloak back-channel logout. It is part of the "
        "session token (see _get_session_token_fields), so incrementing it "
        "invalidates all of this user's active Odoo sessions.",
    )

    def _get_session_token_fields(self):
        # Adding our epoch to the session-token fields lets a back-channel
        # logout invalidate every active session of the user just by bumping it.
        return super()._get_session_token_fields() | {"keycloak_logout_epoch"}

    @api.model
    def _keycloak_backchannel_logout(self, provider, sub=None, sid=None):
        """End Odoo sessions for the subject of a Back-Channel Logout Token.

        Matches users by the stable oauth_uid (sub). Session-specific logout by
        `sid` alone is not supported (Odoo does not persist the Keycloak sid per
        session); such tokens fall back to no-op with a log line.
        """
        if not sub:
            _logger.info("Back-channel logout without sub (sid=%s) — skipped", sid)
            return self.browse()
        users = self.sudo().search(
            [("oauth_provider_id", "=", provider.id), ("oauth_uid", "=", sub)]
        )
        for user in users:
            user.keycloak_logout_epoch = (user.keycloak_logout_epoch or 0) + 1
        return users

    # ------------------------------------------------------------------ #
    #  Sign-in / provisioning                                            #
    # ------------------------------------------------------------------ #

    def _auth_oauth_signin(self, provider, validation, params):
        """Add ЦПФ Keycloak specifics around the standard OAuth sign-in.

        - enforce email_verified (ТЗ §5.5, §6.2);
        - let auth_oauth/auth_oidc match/create the user by the stable sub;
        - reconcile Odoo groups from Keycloak roles on every login (ТЗ §5.4).
        """
        provider_rec = self.env["auth.oauth.provider"].sudo().browse(provider)
        keycloak = provider_rec.is_keycloak

        oauth_uid = validation.get("user_id") or validation.get("sub")
        existed = keycloak and bool(
            self.sudo().search_count(
                [("oauth_uid", "=", oauth_uid), ("oauth_provider_id", "=", provider)]
            )
        )

        if keycloak:
            self._keycloak_check_nonce(provider, validation)
            self._keycloak_check_email_verified(provider_rec, validation)
            if not existed:
                # JIT provisioning: the SSO user is already authenticated by
                # Keycloak, so create the account directly instead of going
                # through Odoo's invitation-gated signup() (default scope is
                # 'on invitation', which would otherwise reject the login).
                vals = self._generate_signup_values(provider, validation, params)
                # no_reset_password: SSO users authenticate via Keycloak, so
                # suppress the "set your password" signup e-mail auth_signup
                # would otherwise send on user creation (ТЗ §5.3).
                self.sudo().with_context(no_reset_password=True).create(vals)

        login = super()._auth_oauth_signin(provider, validation, params)

        if keycloak and login:
            user = self.sudo().search(
                [("oauth_uid", "=", oauth_uid), ("oauth_provider_id", "=", provider)],
                limit=1,
            )
            if user:
                if not existed:
                    provider_rec._keycloak_audit(
                        "jit_create",
                        oauth_uid=oauth_uid,
                        user=user,
                        result="success",
                    )
                user._keycloak_reconcile_groups(provider_rec, validation, params)
                provider_rec._keycloak_audit(
                    "login_success",
                    oauth_uid=oauth_uid,
                    user=user,
                    result="success",
                )
        return login

    def _generate_signup_values(self, provider, validation, params):
        """Enrich the created account from Keycloak claims (ТЗ §4.3)."""
        values = super()._generate_signup_values(provider, validation, params)
        provider_rec = self.env["auth.oauth.provider"].sudo().browse(provider)
        if not provider_rec.is_keycloak:
            return values

        given = (validation.get("given_name") or "").strip()
        family = (validation.get("family_name") or "").strip()
        full = " ".join(part for part in (given, family) if part)
        if full:
            values["name"] = full
        elif validation.get("name"):
            values["name"] = validation["name"]

        # preferred_username is only a fallback login when no e-mail is present.
        if not validation.get("email") and validation.get("preferred_username"):
            values["login"] = validation["preferred_username"]

        return values

    # ------------------------------------------------------------------ #
    #  Helpers                                                            #
    # ------------------------------------------------------------------ #

    def _keycloak_check_nonce(self, provider, validation):
        """Validate the id_token nonce against the one we issued (ТЗ §6.2).

        auth_oidc generates a nonce but never checks it. The nonce we sent was
        stashed in the session by KeycloakOpenIDLogin.list_providers; here we
        compare it to the id_token's nonce claim to block token replay.

        Fail-closed on a mismatch (replay/attack); fail-open when no nonce was
        stored (e.g. session lost, or in unit tests without an HTTP request) so
        legitimate users are not locked out by session edge cases.
        """
        if not request:
            return
        stored = dict(request.session.get("keycloak_nonces") or {})
        expected = stored.pop(str(provider), None)
        request.session["keycloak_nonces"] = stored  # one-time use
        if expected is None:
            _logger.warning(
                "Keycloak nonce not found in session; skipping nonce check"
            )
            return
        if validation.get("nonce") != expected:
            provider_rec = self.env["auth.oauth.provider"].sudo().browse(provider)
            provider_rec._keycloak_audit(
                "login_denied",
                oauth_uid=validation.get("user_id") or validation.get("sub"),
                result="denied",
                reason="nonce_mismatch",
            )
            _logger.warning("Keycloak nonce mismatch — replay protection triggered")
            raise AccessDenied(_("Authentication failed (nonce mismatch)."))

    def _keycloak_check_email_verified(self, provider_rec, validation):
        """Block login/provisioning when the e-mail is not verified."""
        if not provider_rec.enforce_email_verified:
            return
        verified = validation.get("email_verified")
        if verified in (True, "true", "True", 1):
            return
        provider_rec._keycloak_audit(
            "login_denied",
            oauth_uid=validation.get("user_id") or validation.get("sub"),
            result="denied",
            reason="email_not_verified",
        )
        _logger.info("Keycloak login refused: email_verified is not true")
        raise AccessDenied(_("Your e-mail is not verified in Keycloak."))

    def _keycloak_reconcile_groups(self, provider_rec, validation, params):
        """Add groups for present roles, remove groups for absent roles.

        Only groups that appear in this provider's mapping table are touched;
        groups a user has for other reasons are left untouched.
        """
        self.ensure_one()
        mappings = provider_rec.role_mapping_ids.filtered("enabled")
        if not mappings:
            return
        roles = provider_rec._keycloak_extract_roles(validation, params)
        oauth_uid = validation.get("user_id") or validation.get("sub")

        managed = mappings.mapped("group_id")
        wanted = mappings.filtered(
            lambda m: m.keycloak_role in roles
        ).mapped("group_id")
        unwanted = managed - wanted

        commands = [Command.link(g.id) for g in wanted]
        commands += [Command.unlink(g.id) for g in unwanted]
        if not commands:
            return
        try:
            # Odoo 19 renamed res.users.groups_id -> group_ids.
            self.sudo().write({"group_ids": commands})
            # Force constraints (e.g. one-user-type) to run now so a conflict is
            # caught here rather than surfacing later as a raw traceback.
            self.env.flush_all()
        except ValidationError as exc:
            # e.g. the mapped roles grant conflicting user-type groups
            # (portal vs internal). Fail the login cleanly instead of leaking a
            # raw traceback, and record it for the administrator.
            provider_rec._keycloak_audit(
                "login_denied",
                oauth_uid=oauth_uid,
                user=self,
                result="denied",
                reason="group_mapping_conflict: %s" % exc,
            )
            _logger.warning(
                "Keycloak role mapping produced conflicting groups for %s: %s",
                self.login,
                exc,
            )
            raise AccessDenied(
                _(
                    "Your Keycloak roles map to conflicting Odoo access groups. "
                    "Please contact an administrator."
                )
            ) from exc
        provider_rec._keycloak_audit(
            "groups_reconciled",
            oauth_uid=oauth_uid,
            user=self,
            result="success",
            reason="roles=%s" % sorted(roles),
        )
