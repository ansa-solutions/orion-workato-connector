# Orion Advisor — Workato Connector

Custom Workato connectors for the [Orion Advisor API](https://developers.orionadvisor.com/).

## What is in this repo

| File | Status |
|------|--------|
| `orion_advisor_connector.rb` | **Live.** "Orion Advisor Solutions" — the connector currently deployed in Workato. Mirrored here verbatim from the Workato editor. |
| `orion_connection_only.rb` | **Legacy.** Connection-only stub of the previous connector, kept for auth debugging. Does not match the live connector. |

The previous connector — "Orion Advisor", a service-account + impersonation design with
polling triggers and a custom-request escape hatch — was replaced, not evolved. It is still
available at commit `775b3f8` if the impersonation approach is needed again.

> **Keep this file verbatim.** `orion_advisor_connector.rb` is a straight copy of what runs in
> Workato, with no local edits or added comments, so the two can be diffed directly. Fix things
> in Workato first, then re-sync here.

## Authentication — OAuth 2.0 (authorization code), per advisor

Each advisor authorizes their own connection; there is no shared service account and no
impersonation. At sign-in the connector exchanges the code at
`POST {base}/api/v1/Security/Token`, then calls the identity endpoint
(`/api/v1/Authorization/User` by default) and stores the returned email as the connection owner
plus `user_email` / `user_id` / `rep_id`.

Client credentials are sent as **form-urlencoded body fields** by default. The
**Client authentication** field can switch to HTTP Basic, or to both (diagnostic only —
RFC 6749 §2.3.1 forbids mixing, and many servers answer with a bare 401 and no body).

### Connection fields

| Field | Notes |
|-------|-------|
| Environment | Full host URL. Staging (default) or Production. Must match where the OAuth app is registered. |
| Client ID / Client Secret | Issued by Orion. |
| Client authentication | `body` (default), `basic`, or `both`. |
| Send App header on token requests | Off by default; data endpoints always send `App: OrionConnect`. |
| Redirect URI | `https://www.workato.com/oauth/callback` — must be registered with Orion. |
| Scope | Optional, space delimited. |
| Token header prefix | `Bearer` (default) or `Session`. See the open issues below. |
| Identity endpoint path | `/api/v1/Authorization/User`. Called at sign-in and by Get Signed In User. |
| Mask account numbers everywhere | On by default. Leaves only the last 4 on account-number fields. |

## Actions (21)

**Identity** — Get Signed In User (live Orion lookup on every call, plus optional JWT-claim echo).

**Clients** — List Clients · List Clients (Grid View) · Get Client Detail (standard or
`Verbose/{id}` with `expand`) · Get Client Registrations.

**Accounts** — List Accounts (Grid View) · Search Accounts (Simple) · Get Account Value ·
Get Account Asset Values (with cash rollup) · Get Account Transactions (with withdrawal rollup).

**Rep-level books** — Get Beneficiaries (by Rep) · Get Systematics (by Rep) · Get RMD (by Rep).
All three fetch the whole rep book and filter client-side to supplied account IDs.

**Reference** — List Registrations · List Transaction Types · List Portfolio Assets.

**Billing** — List Billing Clients · List Billing Schedules.

**Untested against staging** — Get Household Portfolio Cards ·
Get Performance & Allocation Summary · Get Benchmark & Risk Profile.

## Scoping model — read this before building a recipe

Scope is **not** enforced server-side. Orion returns the whole tenant (~56,000 households) when
`representativeId` is omitted. The connector reports what it did rather than blocking:

- `repScoped` — FALSE means the result is tenant-wide. Assert on it before showing anything.
- `distinctRepIds` — more than the one rep you scoped to means scoping did not take effect.
- `filtered` / `rowsBeforeFilter` / `unmatchedAccountIds` / `idFormatWarning` — on the rep-level
  books, these distinguish "no match" from "none on file". An empty beneficiary or RMD result is
  never on its own evidence that none exists.
- `zeroIsUnverified` — a $0 withdrawal total that came from a failed match, not a real zero.

Feed rep IDs from the entitlement table. Get Signed In User frequently returns a null `rep_id`.

## Open issues (from the 2026-08-29 review, not yet fixed)

Deliberately left as-is so this file stays byte-identical to Workato. Fix in Workato, then re-sync.

1. **Token prefix default.** Defaults to `Bearer`; Orion data endpoints use `Session`. Sign-in
   succeeds and data calls 401.
2. **Refresh path unverified.** The previous connector refreshed with the refresh token as a
   `Bearer` Authorization header and credentials as HTTP headers — no body. This one sends a
   standard form body. `acquire` is exercised at connect time; `refresh` only fires ~10h later.
   Force a refresh in staging before depending on it. Also, `refresh_on` covers 401 but not 403.
3. **Boolean connection fields** are compared with `== true` / `== false`. Checkbox values may
   arrive as `"true"`/`"false"` strings, in which case both toggles are inert.
4. **Search term encoding.** `search_accounts_simple` only escapes spaces before interpolating
   into the URL path.
5. **`identity_path` is not validated** before being concatenated onto the host.
6. **Masking gaps.** Diagnostic modes bypass masking; `mask_rows` is one level deep; RMD /
   beneficiary / systematic rows can carry an unmasked custodian code in `accountId`; error
   messages interpolate up to 500 raw response bytes into job logs.
7. **`row_account_keys` includes the row's own `id`,** which can match an unrelated record.
8. **No pagination.** `top` truncates silently with no indicator that more records exist.
