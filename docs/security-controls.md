# Security controls in the prototype

This page maps the controls of BoK 5.2.2 (SC-01 to SC-12) onto the prototype. For each control it shows
where the control lives, what proves it, and what is left. 5.2.3 works out three controls in detail:
SC-01 with SC-02, SC-03 and SC-09. Those three are implemented as designed, with the changes recorded
in the [ADRs](adr/README.md). The other nine are implemented as far as a single-host laboratory allows,
and the gaps are listed under each.

Paths are relative to `api/src/main/java/nl/fontys/securedesk/` unless they start at the repository
root.

## SC-01: Authentication and session (5.2.3 A)

| Design | Implementation |
|---|---|
| Two-step login. The password step returns a pending session with no authorities | `auth/AuthController` (`/api/auth/login`, `/mfa`, `/password`, `/enrol`), `auth/PendingLogin`, `auth/AuthStage` |
| TOTP per RFC 6238: 160-bit secret, 6 digits, 30 s, ±1 step | `auth/TotpService` and `auth/Base32`, from the mfa-poc. Every window step is compared in constant time |
| A code cannot be replayed within its window | `AppUserRepository.acceptTotpStep`: a conditional `UPDATE … WHERE last_accepted_step < ?`, so two simultaneous uses of one code cannot both win |
| Mandatory for agents and administrators. For requesters, on by default and optional per account | `user/AppUser.isMfaRequired()`. Administrators switch it in the UI (`MFA_REQUIREMENT_CHANGED`, an alert) |
| Ten single-use recovery codes, hashed like passwords | `auth/RecoveryCode`. Each code is Argon2id-hashed and sealed with the pepper; use is an alert (`MFA_RECOVERY_USED`) |
| MFA reset only by an administrator, logged as an alert | `user/UserAdminService.resetMfa` (`MFA_RESET`) |
| Opaque server-side session in a hardened cookie, rotated at login | `__Host-SD-SESSION` (`HttpOnly`, `Secure`, `SameSite=Strict`), `auth/AuthSessions`, [ADR 0006](adr/0006-server-side-sessions.md) |
| Sessions end on privilege change | The security stamp is checked on every request in `auth/SessionValidationFilter` (`SESSION_REVOKED`) |
| Idle and absolute timeouts | 15 minutes idle, 8 hours absolute (`SESSION_EXPIRED`) |
| Step-up for administrative actions (UC-05) | `@RequiresRecentAuthentication` with a 10-minute window, `auth/RecentAuthenticationInterceptor`, `POST /api/auth/reauth`. `ArchitectureTest` requires the annotation on every state-changing `Admin*` endpoint |

**Proof:** `auth/AuthenticationFlowTest`, `auth/TotpServiceTest` and `auth/Base32Test` (both ported
from the mfa-poc), and the end-to-end walk-through in [demonstrations.md](demonstrations.md).

**Left:** TOTP is phishable through a real-time relay; WebAuthn is the next step (5.2.3 A). Sessions
live in one API instance's memory.

## SC-02: Credential storage and anti-automation (5.2.3 A, PoC 6.3)

| Design | Implementation |
|---|---|
| Argon2id, per-user salt, OWASP parameters | `crypto/Argon2id` and `crypto/StoredHash` from the password PoC: m=19456 KiB, t=2, p=1, 16-byte salt, 32-byte hash. Parameters read back from storage are bounded ([ADR 0003](adr/0003-password-poc-classes.md)) |
| Pepper held apart from the database | `crypto/Pepper`, `crypto/SealedBox`: AES-256-GCM over the whole record, with associated data `password:<user id>`. Rotation re-seals every record at start-up (`crypto/KeyRotation`) ([ADR 0002](adr/0002-pepper-seals-the-hash-record.md)) |
| Rehash on parameter change | `crypto/PasswordHasher` reports `OK_REHASHED`, and `AuthService` stores the new record (`PASSWORD_REHASHED`) |
| Tampered record detected | `PasswordHasher` reports `TAMPERED` (`CREDENTIAL_TAMPERED`, an alert); the user sees the generic failure |
| No account enumeration | The same response for every failure. An unknown user is verified against a dummy record, so the timing matches |
| Breached-password check, no composition rules, no forced rotation | `crypto/PasswordPolicy` from the PoC: 15 to 128 characters, NFC, the NCSC top-100k blocklist (`common-passwords.txt`), refuses passwords that contain the username or display name, no composition rules |
| Progressive delay and lockout per account | `auth/LoginThrottleService`: 0, 1, 2, 4, 8 s, and a lock for 15 minutes after 10 failures in 15 minutes. It is keyed on the submitted username, so it applies to unknown names as well, and the row is locked while it is updated |
| Rate limiting per IP | Nginx `limit_req`: 20 per minute (burst 10) on `/api/auth/{login,mfa,enrol,password,reauth}` (`web/nginx/securedesk.conf`) |
| Argon2id cannot be used to exhaust memory | `PasswordHasher`'s semaphore limits concurrent hashes; extra requests wait on virtual threads |

**Proof:** `crypto/Argon2idTest` (RFC 9106 vector), `StoredHashTest`, `PasswordPolicyTest` and
`PasswordHasherTest` (rehash, tamper, key rotation), plus `AuthenticationFlowTest`, which covers
lockout, delays and identical responses.

**Deviation:** the minimum length is 15 characters, as decided in 6.3.7, not the twelve of 5.2.3 A.

## SC-03: Authorisation (5.2.3 B)

| Design | Implementation |
|---|---|
| Deny by default | `config/SecurityConfig`: only the listed URL patterns are reachable, `anyRequest().denyAll()` |
| A role check on every handler | `@PreAuthorize` on every controller method; `ArchitectureTest` fails the build if one is missing |
| Object-level check in one place | `ticket/TicketAccessService`. Scoped finders such as `findByIdAndRequesterId`; a miss gives 404 (`OBJECT_ACCESS_DENIED`) ([ADR 0005](adr/0005-object-authorisation-in-the-service-layer.md)) |
| The principal comes from the session only | `auth/CurrentUser`; no identifier of the caller is read from the request |
| Internal notes removed server-side | Requester and agent views are separate DTOs (`ticket/TicketDtos`), and the requester query never selects internal comments |
| No mass assignment | Separate request DTOs per role, and `fail-on-unknown-properties=true`: an extra field is a 400 and `INPUT_VALIDATION_FAILED` |
| Controllers never touch repositories | `ArchitectureTest.controllersDoNotUseRepositories` |
| The last administrator cannot be removed | `UserAdminService` refuses to demote, disable or erase the last active administrator |

**Proof:** `authz/AuthorizationMatrixTest` runs 151 cases: every role against every endpoint, for an
own object and for someone else's. It fails if an endpoint has no row. Also `ArchitectureTest` and
`user/LastAdministratorTest`.

## SC-04: Input handling and output encoding

- **Validation.** Request DTOs are records with Bean Validation (`@NotBlank`, `@Size`, `@Pattern`);
  `common/GlobalExceptionHandler` returns 400 with the field names only.
- **Queries.** All queries go through Spring Data JPA with bound parameters; there is no string-built
  SQL.
- **Clean-up.** `common/TextSanitizer` normalises to NFC and removes control characters and
  bidirectional overrides before free text is stored.
- **Output.** The React front end renders text only; there is no `dangerouslySetInnerHTML`.
- **CSP.** Nginx sends a strict CSP (`default-src 'self'`, no inline script or style, `frame-ancestors
  'none'`), plus HSTS, `nosniff`, `Referrer-Policy: no-referrer`, COOP and CORP
  (`web/nginx/security-headers.conf`). The API's own responses carry `default-src 'none'; sandbox`.
- **CSRF.** A synchroniser token bound to the session; `CSRF_DENIED` on a miss.
- **Errors.** Generic error bodies (`common/ErrorResponse`), with no stack traces or exception names.
  A correlation id lets an administrator find the details in the log.

**Proof:** `ticket/InputHandlingTest`. The walk-through also checks that the browser reports no CSP
violations.

## SC-05: File uploads

- **Allowed types.** PNG, JPEG, PDF and plain text. The type is decided from the bytes, and the
  extension must agree with it (`ticket/ContentInspector`).
- **Active content.** A PDF with `/JavaScript`, `/Launch`, embedded files or rich media is refused.
- **Limits.** 10 MB per file and 10 files per ticket. Nginx enforces the same body size.
- **Storage.** A random UUID name, stored in MySQL outside any web root, and read only through
  `AttachmentService` after the ticket check ([ADR 0004](adr/0004-attachments-in-the-database.md)).
- **Download.** Served with `Content-Disposition: attachment`, `nosniff` and the sandboxing CSP.
- **Malware scanning.** The `MalwareScanner` interface exists, but the prototype's implementation
  records `scan: NOT_SCANNED`. This is the residual risk of MU-05 named in 5.2.6.

**Proof:** `TicketFlowTest` covers an executable, HTML named `.png`, HTML named `.html`, an active PDF,
an empty file and an oversize file, and checks each rejection's audit reason. `InputHandlingTest` covers
how types are read from the bytes and how names are cleaned up. The walk-through refuses
`invoice.pdf.exe`.

## SC-06: Data at rest and backups

- **Database accounts.** The application account has DML only on its own tables, and `SELECT, INSERT`
  only on `audit_event`. A separate migrator account owns the schema and runs once
  (`deploy/mysql/init/01-accounts.sh`, `db/mysql/R__grants.sql`).
- **Column encryption.** TOTP secrets are AES-256-GCM with associated data `totp:<user id>`.
- **TLS to MySQL.** TLS 1.3 only, `require_secure_transport`, `REQUIRE SSL` on both accounts. The API
  verifies the server's name against the internal CA.

**Left:** volume encryption and backups are the host's job and are not in the laboratory. That
includes nightly encrypted backups with an offline copy and a tested restore.

## SC-07: Secrets and key management

- **Generation.** Secrets are generated once by `deploy/setup/setup.sh` and kept in `./secrets/`
  (git-ignored). Each service mounts only its own directory, read-only, and the CA key is never
  mounted.
- **Where secrets never go.** There are no secrets in code, images, the compose file or `.env`. The API
  reads them as a config tree.
- **Logs.** Secrets are kept out of the logs by the forbidden-field policy of SC-09.
- **Rotation.** The pepper and TOTP keys rotate by adding a key id ([ADR 0002](adr/0002-pepper-seals-the-hash-record.md)).

**Left:** the vault and short-lived credentials (BoK 6.5) ([ADR 0007](adr/0007-secrets-as-mounted-files.md)).
Secret scanning in CI is not set up yet.

## SC-08: Supply chain

- **Pinned versions.** Maven versions are pinned, and npm uses exact versions with a lock file.
  Base images are pinned by tag, and the GitHub Actions by commit SHA.
- **Updates.** Dependabot covers Maven, npm, Docker and the Actions (`.github/dependabot.yml`).
- **SBOM.** Each build produces a CycloneDX SBOM. For the API it is in the jar
  (`META-INF/sbom/application.cdx.json`) and in the image at `/app/sbom/`. For the front end it is
  a CI artifact.
- **Vulnerability gate.** `npm audit --audit-level=high` fails the build.
- **Runner permissions.** The CI token is read-only (`permissions: contents: read`), and checkout does
  not keep the credentials.

**Left:** container and Maven vulnerability scanning with a failing threshold, and image signing and
verification at deployment.

## SC-09: Logging, audit and detection (5.2.3 C)

| Design | Implementation |
|---|---|
| Event fields of 5.2.3 C | `audit/AuditEvent`, `audit/AuditRecord`; see [event-catalogue.md](event-catalogue.md) |
| Forbidden-field policy | `audit/AuditDetails` refuses forbidden keys, caps values and escapes as JSON. `config/ForbiddenLoggersFilter` silences the SQL-parameter and request-body loggers at any level |
| Append-only below the application | `SELECT, INSERT` grant only. The repository exposes no save or delete. The hash chain uses an explicit `seq` and SHA-256 over canonical JSON (`audit/AuditWriter`, `audit/CanonicalJson`) |
| Tampering detected | `audit/AuditChainVerifier`, two minutes after start-up and then hourly, and on demand from the audit page (`AUDIT_CHAIN_BROKEN`, an alert) |
| Off-host within seconds | `audit/AuditForwarder`: RFC 5424 over TLS 1.3 with a client certificate to rsyslog (`deploy/collector/rsyslog.conf`). The collector accepts only the peer `securedesk-api` |
| No log injection | Values are JSON fields, never concatenated. RFC 5424 structured-data values are escaped |
| Alerting on privileged actions | An `alert` flag per event type, plus the detection rules R1–R5 in [event-catalogue.md](event-catalogue.md) |
| Correlation | `X-Request-ID` from Nginx, in Nginx's JSON access log, the application log and every audit event |

**Proof:** `audit/AuditTrailTest` covers the chain, tampering, deletion and rolled-back changes.
`audit/AuditDetailsTest` is the serialiser test, `audit/LogHygieneTest` searches every stream for
marker secrets, and `audit/EventCatalogueTest` keeps the code and the catalogue in step. The live
tamper demonstration is in [demonstrations.md](demonstrations.md).

## SC-10: Availability and resilience

- **Request limits.** Nginx rate limits for authentication, uploads and the API, and a body-size limit
  (1 MB, or 11 MB for uploads).
- **Queries.** Pagination is mandatory with at most 50 rows per page (`common/PageResponse`), and
  queries time out after 5 seconds.
- **Containers.** Each container has memory and pid limits, a health check and `restart:
  unless-stopped`.
- **Audit forwarding.** A bounded queue holds events while the collector is unreachable.

**Left:** a single instance without failover, and no backups (see SC-06). This is the residual risk
of MU-11 named in 5.2.6.

## SC-11: Privacy and retention

- **Minimal user record.** Username, name, work e-mail and role.
- **Retention.** The period is configurable by the administrator: 24 months by default, with a hard
  maximum of 60 months set by the deployment (`admin/RetentionService`). A nightly job deletes closed
  tickets past the period (`RETENTION_PURGE`).
- **Erasure.** Erasing a user (SR-10) removes the personal data and credentials, deletes the tickets
  they filed and unassigns the tickets assigned to them (`USER_ERASED`).
- **Notifications.** The address is always taken from the user record, never from the request. A mail
  holds only the ticket number and a link, never content (`notify/TicketNotifier`).

**Proof:** `ticket/RetentionTest` and `user/UserAdministrationTest`.

## SC-12: Platform hardening and network

- **Zones.** Five zones as Docker networks; `app`, `data`, `monitoring` and `mail` are `internal`, so
  they have no route out.
- **Exposure.** Only Nginx publishes a port, and only on `127.0.0.1`.
- **TLS on every hop.**
  - Browser to Nginx: TLS 1.3 and HTTP/2.
  - Nginx to the API: mutual TLS.
  - API to MySQL: TLS 1.3, with the server name verified.
  - API to the collector: mutual TLS.
  - API to the mail relay: STARTTLS required, with the server identity checked.
- **CA.** One internal EC P-256 CA.
- **Containers.**
  - Non-root users in the web, API, collector and MySQL containers.
  - `read_only` root filesystems for web, API, migration and collector.
  - `cap_drop: ALL` and `no-new-privileges` for every long-running service.
  - Log rotation (10 MB × 5).
- **Actuator.** The API's actuator listens only on the container's loopback, and Nginx answers 404 for
  `/actuator`.

**Left:** the bastion with MFA and the management zone; a default-deny host firewall. All zones share
one host (the residual risk of SC-12 named in 5.2.6).

## Misuse cases

| Misuse case | Controls in the prototype | Evidence |
|---|---|---|
| MU-01 Credential attack | SC-01, SC-02, SC-09 | `AuthenticationFlowTest`; `ACCOUNT_LOCKED`; rule R1 |
| MU-02 Session hijacking | SC-01, SC-04, SC-09 | Cookie flags, rotation, security stamp, CSRF; `SESSION_REVOKED` |
| MU-03 Read another user's ticket | SC-03, SC-05, SC-09 | `AuthorizationMatrixTest`; `OBJECT_ACCESS_DENIED`; rule R2 |
| MU-04 Stored XSS | SC-04, SC-03, SC-09 | Text rendering, strict CSP, `TextSanitizer` |
| MU-05 Malicious upload | SC-05, SC-12, SC-09 | `ContentInspector`; `UPLOAD_REJECTED`. Scanning is a stub |
| MU-06 Privilege escalation | SC-03, SC-04, SC-09 | Matrix test, role DTOs, step-up; `USER_ROLE_CHANGED`; rule R3 |
| MU-07 Direct data extraction | SC-04, SC-06, SC-02, SC-12 | Parameterised queries, sealed credentials, least-privilege account, internal networks |
| MU-08 Cover tracks | SC-09, SC-06, SC-03 | Grants, hash chain, off-host copy; rule R5 |
| MU-09 Steal secrets | SC-07, SC-08, SC-09 | Per-service secret mounts, forbidden-field policy, `LogHygieneTest` |
| MU-10 Poison the release | SC-08, SC-07, SC-12 | Pinned versions, SBOM, `npm audit`. No signing yet |
| MU-11 Denial of service or destruction | SC-10, SC-12, SC-06 | Rate and size limits, pagination, timeouts. No backups yet |
| MU-12 Excessive personal data | SC-11, SC-03, SC-09 | Retention job, erasure, minimal record |
| MU-13 Content leaves through mail, logs or errors | SC-09, SC-04, SC-11, SC-03 | Notifications carry the number only, generic errors, forbidden fields |
