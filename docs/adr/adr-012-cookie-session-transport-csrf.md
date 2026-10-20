# ADR-012: Cookie-Based Session Transport with Double-Submit CSRF Protection

**Status:** Accepted
**Date:** 2026-10-19
**Author:** Stellar MarketPay backend team (issue #1777)
**Stakeholders:** Auth flow (`/api/auth`), all cookie-authenticated state-changing routes, frontend Axios client

## Context

Issue #1777 asked us to determine how authentication tokens actually travel between client and server, because the repository carried CSRF machinery (`src/middleware/csrf.js`, the `csrf-csrf` and `cookie-parser` dependencies, `backend/tests/csrf.test.js`, and frontend double-submit helpers) that `src/server.js` never installed. That left two mutually exclusive readings:

1. Tokens are **header-only** (Bearer) — in which case the CSRF middleware and dependencies are dead weight and should be deleted.
2. Tokens are **cookie-transported** — in which case every state-changing endpoint is CSRF-exposed until the middleware is wired in.

Audit of the actual auth flow (as of this ADR):

- `services/authTokens.js` `setAuthCookies()` writes the access JWT as an HttpOnly `token` cookie (15 min) and the refresh token as an HttpOnly `refreshToken` cookie (7 days), with `SameSite=Strict`.
- `middleware/auth.js` `verifyJWT()` reads the `token` **cookie first** and only falls back to the `Authorization: Bearer` header.
- `routes/auth.js` issues the cookie pair on login/refresh and mints the non-HttpOnly `csrf-token` cookie via the `csrf-csrf` doubleCsrf machinery.
- The frontend (`frontend/lib/api/client.ts`, issue #451) already fetches `GET /api/auth/csrf-token` and attaches `X-CSRF-Token` on every mutating request.

The flow is therefore genuinely cookie-authenticated. Because browsers attach cookies to cross-site requests automatically, relying on `SameSite=Strict` alone is not sufficient defense (Safari and some corporate proxies weaken SameSite; subdomain attacks and SameSite-none downgrade scenarios remain). Reading #2 holds.

## Decision

Keep cookie-based session transport (with a Bearer fallback for first-party API clients) and wire double-submit CSRF protection **end-to-end** in `src/server.js`:

```js
app.use(cookieParser());        // populates req.cookies for getSessionIdentifier()
app.use(doubleCsrfProtection);  // src/middleware/csrf.js — before all route mounts
```

`X-CSRF-Token` (plus the legacy `X-XSRF-Token` alias) was added to the server's CORS `allowedHeaders` so browser preflights do not strip the header.

No dead code is removed: the middleware, dependencies, tests, and frontend helpers all become load-bearing with this wiring.

## Rationale

### Why double-submit cookie (csrf-csrf) instead of removing CSRF support?

Refresh tokens **must** be cookie-transported to be HttpOnly (a JS-readable refresh token defeats the point of rotating, replay-revoking sessions). Once any credential rides in a cookie, CSRF protection is mandatory, not optional.

### Why not header-only tokens (remove the cookies)?

Rejected: it would expose the refresh token to XSS via `localStorage`/`sessionStorage`, break the existing `setAuthCookies` rotation contract, and require a rewrite of the already-shipped frontend client.

### Why not rely on `SameSite=Strict` alone?

Rejected as a sole mitigation: browser defaults drift, some enterprise environments downgrade `SameSite`, and `SameSite` does not defend against same-site subdomain compromise. Double-submit adds an independently verifiable, HMAC-signed second factor bound to the session identifier (`getSessionIdentifier` keys tokens to the `refreshToken` cookie).

## Consequences

### Positive

- ✅ All cookie-authenticated mutations (`POST/PUT/PATCH/DELETE` outside the exempt paths) are CSRF-checked before reaching route handlers.
- ✅ CSRF tokens rotate with the session (stampeded in `setAuthCookies`) so a pre-refresh token cannot be replayed.
- ✅ Existing `backend/tests/csrf.test.js` and `src/routes/auth.test.js` CSRF assertions now exercise the real wiring.

### Negative

- ❌ Non-browser clients that send cookies must also fetch and echo `X-CSRF-Token` (Bearer-only clients are unaffected — `shouldSkipCsrf()` skips them when no auth cookie is present).
- ❌ `CSRF_SECRET` is now mandatory in production; `csrf.js` fails startup without it.

## Implementation Details

- Exempt paths (`shouldSkipCsrf`): safe methods, `/api/auth/*` bootstrap, `/api/health*`, `/metrics`, `/api/docs*`, `/api/public/*`, `/api/developer/*` (API-key auth), and Bearer requests carrying no `token`/`refreshToken` cookie.
- Cookie attributes: `csrf-token` is non-HttpOnly (readable by design — the frontend echoes it), `SameSite=Strict`, `Secure` in production.
- Secret handling: `getCsrfSecret()` refuses to boot production without `CSRF_SECRET`.

## Related ADRs

- [ADR-004](./adr-004-sep10-authentication.md) — SEP-10 wallet authentication (issues the tokens this ADR transports)
- [ADR-008](./adr-008-redis-session-cache.md) — session infrastructure

## References

- Issue #451 (double-submit pattern introduction), issue #1129 (shared token minting), issue #1777 (this wiring)
- OWASP CSRF Prevention Cheat Sheet — synchronizer token / double-submit patterns
