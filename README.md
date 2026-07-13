# auth_keycloak — Keycloak SSO for Odoo 19 (ИС «ЦПФ»)

Регистрация и авторизация пользователей через Keycloak по Single Sign-On (OIDC).
Тонкий слой поверх OCA `auth_oidc`; собственная реализация OIDC не пишется.

> Статус: **в разработке (Этап 2)**. Подробная документация (`README.rst`),
> журнал аудита, меню и переводы — в работе (Поток 2).

## Что делает модуль

- SSO-вход через Keycloak (Authorization Code Flow + PKCE S256, RS256/JWKS —
  из `auth_oidc`);
- JIT-провижининг учётной записи по устойчивому `sub`, проверка `email_verified`;
- сопоставление ролей Keycloak → группам Odoo (таблица, реконсиляция при входе);
- единый выход: RP-initiated (redirect на `end_session_endpoint`) и
  Back-Channel Logout (`/auth_keycloak/backchannel_logout`);
- кнопка «Проверить соединение» (discovery + JWKS);
- хук аудита (модель `auth.keycloak.audit.log` — Поток 2).

## Зависимости

- Odoo 19 core: `auth_oauth`
- OCA `auth_oidc` (репозиторий `OCA/server-auth`, ветка `19.0`)
- Python: `python-jose`

## Установка

1. Положить рядом с этим модулем `auth_oidc` из `OCA/server-auth` (19.0).
2. Установить python-зависимость: `pip install "python-jose[cryptography]"`.
3. Добавить путь к модулям в `addons_path`, обновить список приложений,
   установить **auth_keycloak** (потянет `auth_oidc`).
4. Настроить провайдера: *Settings → Users → OAuth Providers* — включить
   «Keycloak provider», задать базовый URL и realm, нажать «Проверить соединение»,
   заполнить таблицу соответствия ролей.

## Тесты

```
odoo -d <db> -u auth_keycloak --test-enable --test-tags /auth_keycloak --stop-after-init
```

## Лицензия

AGPL-3 (производный от `auth_oidc`).
