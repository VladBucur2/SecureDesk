# 0001. Authentication is built into the API

## Context

The OWASP Secure-by-Design framework assumes a central identity provider (an OIDC provider such as
Keycloak or Entra ID) in front of every application. SecureDesk is sold to SMEs that often have none. And
implementing authentication correctly is one of the learning goals of this semester (BoK 5.2.3 A).

## Decision

The API authenticates users itself. It uses a password stored per ADR 0002 and ADR 0003, and a TOTP
second factor per RFC 6238, taken from the mfa-poc. The flow has two steps: `POST /api/auth/login`
returns a pending session with no authorities, and only `POST /api/auth/mfa` (or the enrolment) turns it
into a signed-in session. The pending stages come in a fixed order, and `AuthStage` documents why:

1. `MFA` comes first, so a temporary password alone cannot set a new password on an account that has a
   factor.
2. `PASSWORD_CHANGE` comes next.
3. `ENROL` comes last, so whoever knew a temporary password cannot enrol a device of their own.

## Consequences

- All of SC-01 and SC-02 is this project's code, so it is covered by the tests in `auth/` and `crypto/`.
  Those tests include the generic-response, timing-equalisation and replay tests of 5.2.3 A.
- TOTP is phishable through a real-time relay. WebAuthn would close that and is the next step. The code
  keeps the factor behind `AuthService.checkCode`, so adding a method there does not touch the
  controllers.
- A customer that has an identity provider cannot use it yet. OIDC login would be another way to reach
  the same `AuthSessions.signIn`.
