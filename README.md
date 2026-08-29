# Orion Advisor — Workato Connector

Custom Workato connectors for the [Orion Advisor API](https://developers.orionadvisor.com/).

## What is in this repo

| File | Status |
|------|--------|
| `orion_advisor_connector.rb` | **Live.** "Orion Advisor Solutions" — the connector deployed in Workato. Mirrored here verbatim from the Workato editor. |

The previous connector — "Orion Advisor", a service-account + impersonation design with
polling triggers and a custom-request escape hatch — was replaced, not evolved. It is still
available at commit `775b3f8`, along with its `orion_connection_only.rb` auth-debugging stub,
if the impersonation approach is needed again.

> **Keep this file verbatim.** `orion_advisor_connector.rb` carries no local edits or added
> comments, so it can be diffed directly against the Workato editor. Fix things in Workato first,
> then re-sync here — with one exception, noted under **Follow-up changes** below, where `main` is
> deliberately ahead pending a paste.

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
| Token header prefix | `Session` (default) or `Bearer`. Orion data endpoints use `Session`. |
| Refresh request style | `auto` (default), `form_body`, or `legacy_headers`. See Follow-up changes. |
| Identity endpoint path | `/api/v1/Authorization/User`. Called at sign-in and by Get Signed In User. Validated as a relative path. |
| Mask account numbers everywhere | On by default. Leaves only the last 4 on account-number fields, recursively. |
| Refuse tenant wide results | Off by default. When on, unscoped list calls raise instead of returning the tenant. |

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
`representativeId` is omitted. By default the connector reports what it did rather than blocking —
switch on **Refuse tenant wide results** to make an unscoped list call raise instead:

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

## Follow-up changes — merged, pending paste into Workato

> **`main` is ahead of the Workato editor for these.** They are merged here but are not live until
> `orion_advisor_connector.rb` is pasted into the editor and confirmed. Until that happens this
> file is the intended state, not the running state. Delete this warning once the paste lands.

These address the items left open after the 2026-08-29 fixes.

**Refresh resilience.** New `Refresh request style` connection field, default `auto`. The refresh
path is the one thing nothing has exercised: `acquire` runs at connect time, `refresh` only fires
at the ~10h expiry, and the previously working connector used a completely different shape
(refresh token as a `Bearer` header, credentials as HTTP headers, no body). `auto` tries the
standard RFC form body first and falls back to that legacy shape rather than letting the
connection die overnight. If both fail, the error carries both attempts' messages. `form_body` and
`legacy_headers` pin one shape once you know which is right.

**Structural scope guard.** New `Refuse tenant wide results` connection checkbox, default off.
When on, `List Clients`, `List Clients (Grid View)` and `List Accounts (Grid View)` raise instead
of returning data if no representative, client, account, or registration filter was supplied.
Orion does not enforce advisor scope on this connection type, so short of returning to
impersonation this is the only guard that is structural rather than procedural. `repScoped` now
also counts a Client ID as scoping, which it always was in practice.

**Paging, honestly labelled.** `Skip` input added to the three list actions plus
`List Billing Clients`, along with `pagingUnverified`, `pageFirstId` and `pageLastId` outputs.
**Orion is not confirmed to support `skip` on these routes.** If it is ignored, a recipe looping
on it gets the same page forever and believes it is paging — so the flag is on by default whenever
`Skip` is set, and `pageFirstId` gives the recipe something to assert against. Verify against a
known-large rep book before building anything on it.

**Shared schemas.** New `object_definitions` with `client_row` and `account_row`. The client and
account shapes were declared inline per action and had drifted: the plain Clients list was missing
`homePhone` and `isDataSharingEntity`, and the Simple account search was missing everything the
Grid view returns. Both are unions now, which is safe because Orion passes extra fields through
and returns absent ones blank.

**Tighter hints and descriptions.** The field hints had grown into paragraphs carrying things only
the build team cared about, which buried the parts a recipe builder needs. Removed the internal
ticket codes (F1/F2/F4/F6, Runbook T7, A-04) and the 40 "Confirmed live" provenance notes, cut the
multi-sentence hints to one line each, and dropped hints that said nothing actionable. Descriptions
now say what an action returns instead of repeating its title. The warnings that stop someone
reporting a wrong number to an advisor — `zeroIsUnverified`, `repScoped`, `idFormatWarning`,
`truncated`, and the fee-schedule "never parse a rate from this" — were kept deliberately.

**Get Account Asset Values against the published contract.** Checked the action against the Swagger
pages for `/Portfolio/Accounts/{key}/Assets/Value` and its dated sibling:

- Added `hasValue`, a documented query param on both routes that was missing entirely.
- Removed `costBasis` from the asset schema. Neither response model contains it, so
  `costBasisPopulated` could only ever return null. The hint now points at **List Portfolio
  Assets** with *Include Cost Basis*, which is the route that has the param.
- Added `valuesPopulated` and `cashAssetCount`, and made `cashPercent` null rather than 0 when
  there is nothing to take a percentage of. Staging returns every position with `shares`, `price`
  and `value` at zero while a custodial cash position is plainly present — without these a recipe
  cannot tell "no cash in this account" from "this tenant carries no valuations", and both render
  to an advisor as $0.00.
- Added `pathCalled` so the caller can see which of the two routes was used.

`asOfDate` is correct as it stands: `/Assets/Value/{asOfDate}` is a documented endpoint in its own
right. Note Swagger types that param as `date-time` while the connector sends `YYYY-MM-DD` — if the
dated call errors while the plain one works, check the format first.

## Still open

- **Triggers.** The old polling triggers were dropped and are not restored here. They relied on
  `orderBy=id desc` and monotonic ids, neither confirmed for this tenant, and rebuilding them on
  the same assumptions would reintroduce exactly the kind of unverified behaviour the rest of this
  work removed. Worth doing deliberately, if anything actually needs event-driven Orion data.
- **Impersonation.** Dropping it moved scope enforcement from Orion to recipe discipline. The
  checkbox above is a guard, not equivalence. If cross-advisor isolation has to be structural,
  running the current action surface on top of impersonation is the real answer.
- **Real pagination.** `Skip` is a probe, not a solution. A confirmed paging contract, or a
  narrowing strategy that never needs one, is still outstanding.
