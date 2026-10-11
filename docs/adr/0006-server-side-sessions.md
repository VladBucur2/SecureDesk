# 0006. Opaque server-side sessions, no JWT

## Context

SC-01 asks for an opaque server-side session in a hardened cookie, rotated on login and privilege change.
The front end is a single-page application on the same origin as the API, behind Nginx.

## Decision

- The session is the servlet container's, in a cookie named `__Host-SD-SESSION` with the attributes
  `HttpOnly`, `Secure`, `SameSite=Strict` and `Path=/`. The idle timeout is 15 minutes, and
  `SessionValidationFilter` enforces an absolute lifetime of 8 hours.
- When the password step passes, the old session is discarded and a new one starts. At full sign-in,
  and when users change their own password, the id is rotated again and the CSRF token is replaced.
- Every account has a security stamp. A role change, disable, password reset, MFA reset, erasure or
  password change replaces it. Every request compares the session's copy with the database, so the account's
  other sessions end at their next request (`SESSION_REVOKED`).
- CSRF uses a synchroniser token bound to the session (`HttpSessionCsrfTokenRepository`). The SPA reads
  it from `GET /api/auth/session`, keeps it in memory (never in storage or a readable cookie), and sends
  it as `X-XSRF-TOKEN`.
- Step-up: administrative changes need a sign-in or re-authentication within the last 10 minutes
  (`@RequiresRecentAuthentication`). The API answers `403 reauth_required`, and the SPA asks for the
  password or a code and retries.

## Consequences

- Revocation is immediate and needs no deny-list. A stolen cookie is useless from another site
  (`SameSite=Strict`) and unreadable to script (`HttpOnly`). An XSS could still act within the page,
  which the strict CSP (SC-04) makes much harder.
- Sessions live in the API's memory, so a restart signs everyone out. Running more than one API instance
  would need a shared session store, such as Spring Session on MySQL.
