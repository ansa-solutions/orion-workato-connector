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

## Review fixes — applied 2026-08-29

The findings from the 2026-08-29 review are fixed in the connector above and pasted into the
Workato editor, so this file mirrors what is running again.

**Auth and connection**
1. Token header prefix defaults to `Session` (was `Bearer`), and both code fallbacks match.
2. `refresh_on` covers `[401, 403]`.
3. `to_bool` method. Checkbox connection values can arrive as `"true"`/`"false"` strings, which had
   left `token_app_header` and `mask_account_numbers` inert. All boolean reads go through it.
4. `identity_path` method validates the path is a single-slash relative path before it is
   concatenated onto the host, so a value carrying a host or a leading `//` cannot send the access
   token off-domain.
5. Client auth style `basic` no longer also puts `client_id` in the form body.

**Data protection**
6. `mask_any` masks recursively, so nested objects (`portfolio`, `householdMembers`) are covered.
   `mask_rows` and `sanitize_rows` delegate to it, so every call site inherits this.
7. `mask_account_id` masks `accountId` when it is not a plain integer — that is how custodian codes
   like `636-148526` were reaching output unmasked next to a masked `accountNumber`.
8. Diagnostic modes route through `sanitize_any` instead of `scrub_pii`, so raw dumps are masked.
9. `safe_body` scrubs and masks error-response bodies before they reach job logs.
10. `jwtClaimsRaw` is gated behind the `echo_claims` input, default off.

**Correctness**
11. `row_account_keys` no longer matches on the row's own `id`, which could return another client's
    beneficiary, systematic, or RMD rows through an account filter.
12. `zeroIsUnverified` fires whenever a $0 total came from an empty match set, including the typeId
    path — previously the most believable wrong answer was the one flagged as fine.
13. Withdrawal totals sum signed and then take magnitude. `withdrawalNetSigned` and `mixedSigns`
    make a contribution caught by the match rule visible instead of letting it inflate the total.
14. `costBasisPopulated` returns null when Orion returned no `costBasis` field at all, rather than a
    hard `false` that reads as "cost basis is missing". `costBasis` added to the asset schema.
15. `unwrap_array` unwraps common envelope keys instead of turning `{"data":[…]}` into one row.
16. `top` guards test `.nil?` rather than truthiness, so `top: 0` no longer passes through as 0.
17. Search terms containing `/ ? # %` are rejected rather than rewriting the request path.

**Completeness**
18. Every list action returns `truncated`. `top` was a silent truncation knob against a ~56,000
    household tenant.
19. `list_billing_clients` defaults `top` to 1000, down from 50000.

## Still open

- **The refresh path has not been exercised.** `acquire` runs at connect time; `refresh` only fires
  when the ~10h access token expires. The previous connector refreshed with the refresh token as a
  `Bearer` Authorization header and credentials as HTTP headers, no body — this one sends a standard
  RFC form body. If Orion's endpoint is as non-standard on refresh as the old code implies, the
  failure mode is "works all day, breaks overnight". Force a refresh in staging.
- **No pagination.** `truncated` tells you a result was cut off; it does not let you fetch the rest.
  Anything needing the full book still needs a paging strategy.
- **Scope is not enforced server-side.** The connector reports (`repScoped`, `distinctRepIds`) rather
  than blocking. The previous connector pushed this to Orion via impersonation. Worth revisiting if
  cross-advisor isolation needs to be structural rather than procedural.
- **No `object_definitions`.** Client and account schemas are re-declared per action and have already
  drifted between `list_clients` and `list_clients_grid`.
- **No triggers.** The old polling triggers were dropped and not replaced.
