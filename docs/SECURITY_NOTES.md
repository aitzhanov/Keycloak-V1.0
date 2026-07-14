# Security notes for the architect / security review

Two items inherited from OCA `auth_oidc` deviate from ТЗ §6.2 (усиленные
требования ИБ). They are not bugs in `auth_keycloak` itself, but the module is
responsible for these requirements per the ТЗ, so a decision is needed before
the security review (AC-7).

## 1. `nonce` is generated but NOT validated  —  vs ТЗ §6.2 / D5

**Finding.** `auth_oidc` adds a fresh `nonce` to the authorization request
(`controllers/main.py`) but never checks it on the callback: the value is not
stored server-side, and nothing compares it against the `nonce` claim of the
returned `id_token`. So the replay protection the `nonce` is meant to provide
is not actually enforced.

**Current mitigations.** `state` (CSRF) is validated by core `auth_oauth`;
transport is TLS; `id_token` signature (RS256/JWKS) and short lifetime are
checked. These cover most of the practical risk, but not `id_token` replay
specifically.

**Options.**
- **(A) Implement nonce validation in the `auth_keycloak` layer.** Store the
  issued nonce (e.g. in the session, keyed by `state`) in the login controller,
  then compare it to `id_token.nonce` inside our `_auth_oauth_signin` before
  accepting the user. Non-trivial: touches the login flow and MUST be tested
  end-to-end against a real Keycloak (blocked until the test Keycloak / ps.kz
  stand or Мухамбет's data is available).
- **(B) Accept the risk** and document it, relying on state + PKCE + TLS +
  signature + token lifetime.

**Recommendation:** plan (A) for the integration phase (when a live Keycloak is
available to test); until then, record (B) as the interim posture.

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
