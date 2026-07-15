# Decision log — auth_keycloak

## D-001 · Realm (2026-07-14)

**Decision (Руководство):** Odoo connects to the **single existing Keycloak
realm `president-center`** (192.168.16.36:8081). No separate ЦПФ realm(s) are
created for this phase.

**Consequences to record for acceptance (приёмка):**

- **ТЗ §3.4 / D1 (multi-realm, internal + external realms)** — NOT delivered
  as specified; a single realm is used. Needs to be recorded as a formal TZ
  deviation (or the requirement re-scoped).
- **ТЗ UC-02 / §5.2 external self-registration (acceptance AC-2)** — the
  `president-center` realm has `registrationAllowed: false` and no SMTP, so
  self-registration is **out of scope for this phase**. AC-2 must be adjusted
  or moved to a later phase, otherwise acceptance will fail on it.
- **email_verified (§5.5/§6.2, AC-5):** realm has `verifyEmail: false`, so the
  provider is configured with `enforce_email_verified = False`. If real email
  verification is required for production, enable `verifyEmail` + SMTP in
  Keycloak (decision with ИБ).

**Config:** see `docs/provider_president_center.example.xml`. The module itself
stays multi-realm-capable (one `auth.oauth.provider` per realm) — this is only
the deployment choice for the current phase.

**Still blocking the first login:** the `odoo-portal` OIDC client must be
created in `president-center` (Мухамбет) → `client_id` + `client_secret`.
