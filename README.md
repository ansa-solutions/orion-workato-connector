# Orion Advisor — Workato Connector

A custom Workato connector for the [Orion Advisor API](https://developers.orionadvisor.com/).

## Authentication — OAuth 2.0 (authorization code)

The connector uses OAuth 2.0 so **no user id or password is stored**. An Orion user
logs in once via the browser; Workato keeps and auto-refreshes the tokens.
Per Orion's [OAuth guide](https://developers.orionadvisor.com/guides/oauth/):

1. **Authorize:** browser is sent to `{base}/api/oauth/?response_type=code&redirect_uri=…&client_id=…&state=…`
   (path is `/api/oauth/` — **no** version segment, or Orion shows its native login dialog).
2. **Token exchange:** `POST {base}/api/v1/Security/Token` with query params
   `grant_type=authorization_code&code=…&client_id=…&client_secret=…&redirect_uri=…&response_type=code`.
3. Response: `access_token` (~10h JWT), `refresh_token` (375 days), `expires_in`.
4. Every subsequent call sends **`Authorization: Session <access_token>`**.

`refresh_on: [401, 403]` refreshes transparently. **Orion rotates refresh tokens** — the
old token is voided once used, so the connector persists the new `refresh_token` returned
on each refresh.

### Setup
1. **Whitelist the redirect URI with Orion:** `https://www.workato.com/oauth/callback`
   (Orion must register this for your `client_id`).
2. In Workato, enter **Environment**, **Client ID**, **Client Secret**, then click
   **Connect** and log in through Orion. Do **not** use a firm API user account for this
   browser login — Orion disallows it.

### Connection fields
| Field | Notes |
|-------|-------|
| Environment | Production (`api.orionadvisor.com`) or Staging (`stagingapi.orionadvisor.com`) |
| Client ID / Client Secret | Partner credentials provided by Orion |

> No service-account / client-credentials flow exists in Orion — a human must complete the
> browser login once. After ~375 days the refresh token expires and someone re-authorizes.

## What changed vs. the original Python script

The original script used **Basic auth** done incorrectly. This connector uses OAuth instead, but
for reference the script's bugs were: it `POST`ed to the token endpoint (should be `GET`),
put `Authorization`/`client_id`/`client_secret` in the **body** (should be **headers**),
never reused the token, and never sent `Authorization: Session <token>` on API calls.

## Actions
- **Get impersonation token** — mint a token scoped to a rep/client (see below)
- **Search clients** — `GET /api/v1/Portfolio/Clients`
- **Get client by ID** — `GET /api/v1/Portfolio/Clients/{id}`
- **Search accounts** — `GET /api/v1/Portfolio/Accounts`
- **Get account by ID** — `GET /api/v1/Portfolio/Accounts/{id}`
- **Send custom request** — escape hatch to call any Orion endpoint (any verb, query params, body)

Every data action (and Send custom request) has an optional **Impersonation token** input.

## Impersonation (dynamic, per recipe step)

Per Orion's [impersonation guide](https://developers.orionadvisor.com/guides/impersonation/),
impersonation is a token exchange: authenticate normally, then call
`GET /api/v1/security/token` again with `Authorization: Impersonate <service_token>` plus
headers `Entity` (4 = Representative, 5 = Client), `EntityId`, and optional `LoginName`.
That returns a fresh `Session` token scoped to the target user.

**Recipe pattern:**
1. **Get impersonation token** → choose *Representative* or *Client*, enter the Entity ID.
   Returns an **Impersonation token** (~10h lifetime).
2. In any later step (e.g. *Search accounts*, *Send custom request*), drop that token into
   the **Impersonation token** field. That call runs as the impersonated user; leave it
   blank to run as the service account. You can impersonate different users in different
   steps of the same recipe.

### How it works internally
The service OAuth access token only exists inside the connection's `apply` block, so the
connector signals impersonation through flags it sets on the `connection` object, which
`apply` reads:
- `_imp_exchange` → send the service token with the **Impersonate** scheme (minting).
- `_imp_token` → send that token with the **Session** scheme (acting as the user).

This is deterministic regardless of how Workato orders `apply` vs. action-level headers.
> If your Workato runtime freezes the `connection` object inside actions, this technique
> can't set those flags — in that case switch to **connection-level** impersonation
> (one connection per impersonated identity). Ask and I'll add that variant.

## Triggers (polling — Orion REST has no webhooks)
- **New client** — emits clients with an ID higher than any seen before
- **New account** — emits accounts with an ID higher than any seen before

## Assumptions to verify against your Orion entitlements
These were modelled from Orion's standard v1 API; confirm field names and query-param
support for your account, then tighten the schemas:

- The `client` / `account` output schemas list common fields. Orion responses are
  permissive — extra fields pass through, missing ones come back blank. Adjust
  `methods.client_schema` / `methods.account_schema` to match your actual payloads.
- Triggers assume `Portfolio/Clients` and `Portfolio/Accounts` accept `orderBy=id desc`
  and that IDs increase monotonically. If your tenant exposes a `modifiedDate` filter,
  switch the triggers to a `since`-timestamp cursor for "new **or updated**" semantics —
  use **Send custom request** to probe what query params your endpoints accept.
