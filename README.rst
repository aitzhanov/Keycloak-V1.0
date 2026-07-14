=====================================
auth_keycloak — Keycloak SSO for Odoo 19
=====================================

**Module:** ``auth_keycloak``

**Version:** 19.0.1.0.0

**License:** AGPL-3

**Author:** Президентский центр Республики Казахстан (ЦПФ)

.. contents::
   :local:
   :depth: 2


Overview
--------

``auth_keycloak`` is a thin Odoo 19 add-on that turns the standard OCA
``auth_oidc`` module into a production-grade Keycloak SSO integration.

It adds:

* **Role mapping** — Keycloak ``realm_access.roles`` → Odoo ``res.groups``
* **JIT provisioning** — auto-create/update ``res.users`` on first login
* **Single Logout** — RP-initiated + back-channel (Keycloak push)
* **Audit log** — immutable event trail (``auth.keycloak.audit.log``)
* **i18n** — KK / RU / EN


Architecture
------------

::

    Browser ──OIDC Authorization Code + PKCE S256──► Keycloak
               ◄── id_token (RS256) ──────────────────
    Odoo (auth_oidc callback) ──► auth_keycloak layer
                                       ├── role mapping
                                       ├── JIT provisioning
                                       ├── audit log
                                       └── single logout


Dependencies
------------

* Odoo 19 Community or Enterprise
* OCA ``auth_oidc`` 19.0.1.0.0 (from `OCA/server-auth <https://github.com/OCA/server-auth>`_)
* Python package ``python-jose`` (inherited from ``auth_oidc``)


Installation
------------

.. code-block:: bash

    # 1. Clone OCA auth_oidc into your addons path
    git clone -b 19.0 https://github.com/OCA/server-auth.git /opt/odoo/addons/server-auth

    # 2. Clone this module
    git clone https://github.com/aitzhanov/Keycloak-V1.0.git /opt/odoo/addons/auth_keycloak

    # 3. Install python-jose (usually already present via auth_oidc)
    pip install python-jose

    # 4. Restart Odoo and install via Apps menu (search: "Keycloak")


Quick-Start: Configuring the Provider
--------------------------------------

Go to **Settings → Keycloak → (provider list from auth_oidc)**
or navigate to **Settings → Technical → OAuth Providers**.

Field reference
~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Field
     - Description
   * - **Name**
     - Human label shown on the login button, e.g. ``ЦПФ Keycloak SSO``
   * - **Server URL**
     - Keycloak base URL, e.g. ``https://sso.pcrk.kz/``
   * - **Keycloak Realm**
     - Realm name, e.g. ``cpf-external``
   * - **Client ID**
     - OIDC client name registered in Keycloak, e.g. ``odoo-portal``
   * - **Use PKCE**
     - **Must be True** (S256 code challenge, §4.1 TZ)
   * - **Enforce Email Verified**
     - Reject tokens where ``email_verified = false`` (§5.5 TZ)
   * - **Enable Back-Channel Logout**
     - Allow Keycloak to terminate Odoo sessions server-side (§4.4 TZ)
   * - **Scope**
     - ``openid profile email`` (required for JIT and role mapping)

Discovery URL is derived automatically::

    {Server URL}/realms/{Keycloak Realm}/.well-known/openid-configuration

Example (ЦПФ stand)::

    Server URL : https://sso.pcrk.kz/
    Realm      : cpf-external
    Client ID  : odoo-portal
    → Discovery: https://sso.pcrk.kz/realms/cpf-external/.well-known/openid-configuration


Role Mapping
------------

Navigate to **Settings → Keycloak → Role Mappings**.

Each mapping links a **Keycloak role name** (string, case-sensitive) to an
**Odoo group** (``res.groups``).

Predefined mappings for ЦПФ
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 35 35 30

   * - Keycloak Role
     - Odoo Group
     - Notes
   * - ``cpf-portal-user``
     - ``base.group_portal``
     - External portal users
   * - ``cpf-internal-staff``
     - ``base.group_user``
     - Internal employees
   * - ``cpf-admin``
     - ``base.group_system``
     - Administrators

Roles are read from ``realm_access.roles`` in the Keycloak ID token.
At each login the user's ``group_ids`` (Odoo 19) are fully reconciled.

.. warning::

   In Odoo 19 the user groups field is **``group_ids``** (renamed from
   ``groups_id`` in earlier versions). All role-mapping code uses this
   correct name.


JIT Provisioning
----------------

When a user authenticates via Keycloak for the first time and no matching
``res.users`` record exists (matched by ``oauth_uid = sub``), the module
creates a new user automatically using claims from the ID token:

* ``given_name`` + ``family_name`` → ``res.partner.name``
* ``email`` → ``res.users.login`` (only if ``email_verified = true``)
* ``preferred_username`` → fallback login

JIT creation is logged as ``jit_create`` in the audit log.


Single Logout
-------------

RP-Initiated Logout
~~~~~~~~~~~~~~~~~~~

When the user clicks **Log Out** in Odoo:

1. Odoo calls Keycloak's ``end_session_endpoint`` with ``id_token_hint``
   and ``post_logout_redirect_uri``.
2. Keycloak terminates the SSO session across all connected applications.

Back-Channel Logout
~~~~~~~~~~~~~~~~~~~

Keycloak can push a **Logout Token** (JWT) to Odoo's back-channel endpoint:

::

    POST https://portal.pcrk.kz/auth/keycloak/backchannel_logout

Configure this URL in Keycloak → Client → Back-channel logout URL.

Odoo validates the Logout Token (``iss``, ``aud``, ``iat``, ``events``
claim) and immediately invalidates the corresponding Odoo session.


Audit Log
---------

Every SSO event is written to ``auth.keycloak.audit.log``.

View the log at **Settings → Keycloak → Audit Log**.

Event types
~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Event type
     - When
   * - ``login_success``
     - User authenticated successfully via Keycloak
   * - ``login_denied``
     - Authentication rejected (e.g. ``email_verified=false``, unknown sub)
   * - ``jit_create``
     - New user created by JIT provisioning
   * - ``groups_reconciled``
     - User's Odoo groups updated from Keycloak roles
   * - ``backchannel_logout``
     - Back-channel logout token received and processed
   * - ``logout_denied``
     - Back-channel logout token rejected (invalid signature / claims)

.. warning::

   The audit log **never stores** tokens, authorization codes, or
   ``code_verifier`` values (§5.9 TZ).

The log is **read-only** in the UI. Records can only be created by the
system (via ``sudo()``) and cannot be edited or deleted through the
interface.


Security Notes
--------------

* PKCE S256 is mandatory — ``code_challenge_method=S256`` is always used.
* ``state`` and ``nonce`` parameters protect against CSRF and replay attacks.
* JWT claims ``iss``, ``aud``, ``exp``, ``nbf`` are validated on every
  token (clock skew tolerance: 5 s).
* ``emailVerified`` must be ``true`` when ``enforce_email_verified`` is set.
* ``sub`` is the sole stable identifier; ``email`` changes are handled
  safely.
* All communication requires TLS (HTTPS).
* ORM is used exclusively — no raw SQL (protects against SQLi).
* CSRF protection relies on Odoo's built-in token mechanism.


Development Stand
-----------------

Local Keycloak (Docker)::

    docker run -d --name keycloak \
      -p 8081:8080 \
      -e KEYCLOAK_ADMIN=admin \
      -e KEYCLOAK_ADMIN_PASSWORD=admin \
      quay.io/keycloak/keycloak:25.0 start-dev

    # Import demo realm
    # (see docs/demo_local_keycloak.xml in this repo)

Run tests::

    ./odoo-bin -d test_db -i auth_keycloak \
      --test-enable --stop-after-init \
      --log-level=test

Expected: **18+ tests green** (core) + audit log tests.


Changelog
---------

19.0.1.0.0 (2026-07-14)
~~~~~~~~~~~~~~~~~~~~~~~~

* Initial release.
* Core (Stream 1): SSO login, role mapping, JIT, single logout, 18 tests.
* Stream 2: audit log model, UI (list/form/search), KK/RU/EN translations,
  provider data stub, full README.


License
-------

AGPL-3.0 or later — see ``LICENSE`` file.

This module depends on OCA ``auth_oidc`` (also AGPL-3).
Python package ``python-jose`` is MIT-licensed.
