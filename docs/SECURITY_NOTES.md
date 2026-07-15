# Security notes for the architect / security review

One item inherited from OCA `auth_oidc` remains for review; the nonce gap has
been closed. These are requirements the module owns per the ТЗ.

## 1. `nonce` validation  —  ✅ RESOLVED (2026-07-15), vs ТЗ §6.2 / D5

**Was.** `auth_oidc` adds a fresh `nonce` to the authorization request but never
checked it on the callback (no server-side storage, no comparison to the
`id_token.nonce` claim) — so replay protection was not enforced.

**Now.** Implemented in the `auth_keycloak` layer:
- `controllers/main.py` `KeycloakOpenIDLogin.list_providers` stashes the issued
  nonce per provider in the session;
- `res.users._keycloak_check_nonce` compares it to the `id_token.nonce` claim in
  `_auth_oauth_signin` (before provisioning/login), one-time use.
- Fail-closed on mismatch (raises AccessDenied + audit `login_denied` /
  reason `nonce_mismatch`); fail-open when no nonce is stored (session lost /
  unit tests) to avoid locking out legitimate users.

**Verified live** against a local Keycloak: normal login validates the nonce
and succeeds (no skip warning, no mismatch); unit suite still green.

## 2. PKCE uses a static `code_verifier`  —  hardening

**Finding.** `auth_oidc` stores `code_verifier` as a provider field generated
once and reused for every login, instead of a fresh verifier per authorization
request (RFC 7636 intent). PKCE (S256) is present and the verifier never leaves
the Odoo server (it is only sent in the back-channel token request), so the
practical exposure is limited to an Odoo-side secret leak.

**Options.**
- **(A) Per-request verifier** — generate the verifier per login and carry it
  through `state`/session. Overlaps with the nonce work above.
- **(B) Accept** — low severity given the verifier stays server-side.

**Recommendation:** bundle with item 1 if we implement (A); otherwise accept.

---

Both items should be raised with the Архитектор ПО and the Специалист по ИБ so
the decision (implement vs. accept) is on record for acceptance criteria AC-5
and AC-7.

## 3. Stage-1 Keycloak realm findings (president-center, dump 2026-07-14)

The real Stage-1 realm (`192.168.16.36:8081`, realm `president-center`) diverges
from the ТЗ. These are **environment / configuration** items (not module code),
but they gate the security review and several ТЗ requirements. The module is
config-driven and adapts to each via settings, but the realm itself must be
decided/reconfigured.

| Finding (from dump) | ТЗ requirement | Impact / action |
|---|---|---|
| `http://…:8081`, `sslRequired: external` | §6.2 — TLS only | Put an HTTPS front (Nginx) before production. |
| `verifyEmail: false` (and `email_verified` not advertised) | §5.5/§6.2 — login only if verified | Module: set `enforce_email_verified=False` (done in example), OR enable verifyEmail + SMTP in Keycloak. |
| `registrationAllowed: false`, `smtpServer: {}` | UC-02/§5.2 — external self-registration | Feature impossible as-is: enable registration + SMTP, or use a dedicated external realm. |
| Only realm role `user` (no `cpf_*`) | §5.4 — role→group mapping | Create the ЦПФ roles in Keycloak (with the Конструктор прав доступа), then fill the mapping table. |
| No Odoo OIDC client | §7.3 | Мухамбет must create `odoo-portal` (client_id + secret + redirect `…/auth_oauth/signin`). |
| Single realm `president-center` (existing platform realm) | §3.4 — internal + external realms | Decision: reuse existing realm vs stand up dedicated ЦПФ realm(s). |
| Positive: `backchannel_logout_supported: true`, `end_session_endpoint` present, PKCE S256, RS256 | §4.4, §6.2 | Single Logout + PKCE + signature all supported — our logout code applies. |

**Not a real issue:** the dump shows `token`/`jwks`/`userinfo` on `127.0.0.1:8081`
because the collection script ran on the Keycloak host (localhost); when Odoo
queries discovery via `192.168.16.36`, those endpoints come back on the LAN IP.
Confirm Keycloak `frontendUrl`/hostname so production endpoints stay consistent.
