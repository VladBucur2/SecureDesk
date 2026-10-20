# Event catalogue

This is the event catalogue of BoK 5.3.5: the events SecureDesk records and the fields of each.
It is derived from the misuse cases of 5.2, the design of SC-09 in 5.2.3 C, and the observations of the
logging PoC in 6.2. The code version of this list is
[`AuditType`](../api/src/main/java/nl/fontys/securedesk/audit/AuditType.java).
`EventCatalogueTest` fails the build if an event type is missing from this page.

## Where the events go

Every event is written to three places in the same step:

| Where | Form | Purpose |
|---|---|---|
| The `audit_event` table in MySQL | One row per event, hash-chained | The record the administrator reads in the UI (UC-07). The application account has only `SELECT` and `INSERT` on it |
| The API's stdout, logger `AUDIT` | One JSON object per line | `docker compose logs api`. Docker rotates the file at 10 MB × 5 |
| The collector in the monitoring zone | RFC 5424 over TLS with a client certificate (RFC 5425), port 6514 | The off-host copy (rsyslog). `/var/log/securedesk/audit.jsonl` holds one JSON line per event for a SIEM; `audit-rfc5424.log` holds the messages as received |

The application log, which records start-up, errors and framework messages, is a separate stream.
It goes to stdout in Elastic Common Schema JSON. Audit events never depend on the log level. A rule
selects on `category`, `event`, `outcome` and `alert`, not on a level.

## The fields of every event

These are the fields of 5.2.3 C, plus the category and the alert flag.

| Field | Example | Meaning |
|---|---|---|
| `seq` | `48` | Position in the chain: 1, 2, 3, … without gaps |
| `event_id` | `5426b2a9-…` | UUID of the event |
| `ts` | `2026-10-11T09:51:59.566335Z` | UTC, ISO 8601, microseconds |
| `event` | `LOGIN_PASSWORD` | The type from the tables below |
| `category` | `AUTHN` | `AUTHN`, `AUTHZ`, `ACCOUNT`, `CONFIG`, `DATA`, `PRIVACY`, `AUDIT`, `SYSTEM` or `INPUT` |
| `outcome` | `FAILURE` | `SUCCESS`, `FAILURE`, `DENIED` (refused by a control) or `LOCKED` (refused by the lockout) |
| `alert` | `true` | The event should page someone on its own (see below) |
| `actor_id`, `actor`, `actor_role` | `023c…`, `admin`, `ADMIN` | Who did it: `system`/`SYSTEM` for jobs, `-` when no account is known (an unknown username is never written, in case it is a mistyped password) |
| `src_ip` | `172.21.0.1` | The client address as Nginx saw it. Nginx overwrites `X-Forwarded-For`; it never appends to it |
| `session` | `243ad6782d72` | The first six bytes of SHA-256 over the session id. Enough to group the events of one session, but useless for taking the session over |
| `target_type`, `target_id` | `ticket`, `9c1e…` | The object acted on, by UUID |
| `correlation_id` | `6e0d72…` | The request's `X-Request-ID`, set by Nginx and repeated in Nginx's access log and the application log |
| `details` | `{"reason":"bad_password","failed_count":"3"}` | Up to 16 extra keys, listed per event below. Values are capped at 120 characters |
| `prev_hash`, `hash` | 64 hex characters | `hash` = SHA-256 over `prev_hash` and the canonical JSON of this event. The first event chains to 64 zeros |

An event about a change is written when the change's transaction commits. If it rolls back instead,
the event is still written, with outcome `FAILURE` and the detail `rolled_back: true`, because the
action was attempted but not done.

On stdout and at the collector the line also carries `"stream":"audit"`. The collector wraps the line
with the time received, the sender's address, the RFC 5424 `HOSTNAME` and `MSGID` (the event type). It
puts the event under `event`:

```json
{"received":"2026-10-11T09:46:15.810603+00:00","from":"172.19.0.3","hostname":"securedesk-api",
 "msgid":"USER_CREATED","event":{"seq":"1","event":"USER_CREATED","category":"ACCOUNT",
 "outcome":"SUCCESS","alert":false,"actor":"system","actor_role":"SYSTEM", "...": "...",
 "details":{"origin":"bootstrap","role":"ADMIN","username":"admin"},"prev_hash":"0000…","hash":"ea4d…"}}
```

## What is never in an event

These are the forbidden fields of SC-09 and the "keep secrets out" rule of 5.3.4.
[`AuditDetails`](../api/src/main/java/nl/fontys/securedesk/audit/AuditDetails.java) refuses them when the
code tries to add them, so a mistake fails the build in a test rather than leaking in production:

- Passwords, TOTP codes, recovery codes, TOTP secrets, keys, CSRF tokens and session ids. A key that
  contains `password`, `secret`, `token` or `cookie` anywhere is refused.
- Ticket content: titles, descriptions, comments and resolutions. Attachment names and content are
  refused too, as are e-mail addresses and phone numbers. An event names the ticket by its UUID.
- Free text from a request. Validation failures record the field names, never the submitted values.

`LogHygieneTest` drives sign-in, enrolment, password changes and tickets with marker values. It then
searches the database, stdout and the forwarded messages for those markers.
`ForbiddenLoggersFilter` keeps the loggers that would print SQL parameters or request bodies quiet at
any level.

## The catalogue

**Alert** marks an event that a SIEM should page on by itself. Such an event is either what an
attacker with a foothold does next (reset a factor, change a role, issue a temporary password) or
evidence that a control was attacked (a tampered credential, a broken chain). **Outcomes** lists the
values the code writes. The default is `SUCCESS`.

### Authentication (`AUTHN`): MU-01, MU-02

| Event | Alert | Outcomes | Details | When |
|---|---|---|---|---|
| `LOGIN_PASSWORD` | | SUCCESS, FAILURE | `reason` (`unknown_account`, `bad_password`, `no_password`, `tampered`, `disabled`), `failed_count` | Password step of the sign-in. For an unknown username the actor is `-` |
| `LOGIN_BLOCKED` | | LOCKED | | A password or code attempt for a username that is locked. The password is still hashed against a dummy, so the work done is the same as for a real check |
| `ACCOUNT_LOCKED` | yes | LOCKED | | The tenth failure within fifteen minutes, counting password, code and step-up failures. The username is locked for fifteen minutes |
| `MFA_VERIFY` | | SUCCESS, FAILURE | `method` (`totp`, `recovery_code`) or `failed_count` | Code step of the sign-in. A replayed code is a failure. A failure that reaches the limit writes `ACCOUNT_LOCKED` instead |
| `MFA_RECOVERY_USED` | yes | SUCCESS | `remaining` | A single-use recovery code was spent |
| `MFA_ENROL_START` | | SUCCESS | | A new TOTP secret was generated |
| `MFA_ENROL_CONFIRM` | | SUCCESS, FAILURE | `failed_count` | Enrolment confirmed with a code from the new generator, or refused |
| `RECOVERY_CODES_ISSUED` | | SUCCESS | `count` | Ten recovery codes, shown once |
| `LOGIN_COMPLETE` | | SUCCESS | `factors` (1 or 2) | Fully signed in; the session id was rotated |
| `REAUTH` | | SUCCESS, FAILURE, LOCKED | `failed_count` | Step-up before an administrative action. A failure counts toward the lockout |
| `LOGOUT` | | SUCCESS | | Signed out |
| `SESSION_REVOKED` | | SUCCESS | `reason` (`account_changed`) | The account's security stamp changed (role, disable, reset, password), so its other sessions end at their next request |
| `SESSION_EXPIRED` | | SUCCESS | `reason` (`absolute_lifetime`) | Eight hours after sign-in, however active the session was |
| `PASSWORD_CHANGED` | | SUCCESS, FAILURE | `reason` (`bad_current`) | The owner changed the password. On the account page this needs the current one |
| `PASSWORD_REJECTED` | | FAILURE | `reason` (the policy's message) | The policy refused a new password: too short or too long, on the blocklist, contains the username or name, or same as the current one |
| `PASSWORD_REHASHED` | | SUCCESS | | A hash under older Argon2id parameters was replaced at sign-in |
| `CREDENTIAL_TAMPERED` | yes | FAILURE | `record` (`password`, `totp`, `recovery_code`) or `during` (`key_rotation`) | A sealed record failed its AES-GCM check. Someone wrote to the credential columns, or copied one user's record into another's row |

### Authorisation (`AUTHZ`): MU-03, MU-06

| Event | Alert | Outcomes | Details | When |
|---|---|---|---|---|
| `AUTHZ_DENIED` | | DENIED | `reason` (`authorization`), `method`, `path` | A role check refused the request (403) |
| `CSRF_DENIED` | | DENIED | `reason` (`csrf`), `method`, `path` | A missing or wrong CSRF token (403) |
| `OBJECT_ACCESS_DENIED` | | DENIED | `reason` (`not_found`, `not_permitted`) | A ticket or attachment outside the caller's reach. The caller gets 404 either way; only the log says whether the object exists |
| `REAUTH_REQUIRED` | | DENIED | `path` | An administrative action that came more than ten minutes after the last sign-in or step-up |

### Account administration (`ACCOUNT`, `PRIVACY`): UC-05, MU-06, MU-12

| Event | Alert | Outcomes | Details | When |
|---|---|---|---|---|
| `USER_CREATED` | | SUCCESS | `username`, `role`, `origin` (`admin`, `bootstrap`, `demo`) | An account was created |
| `USER_ROLE_CHANGED` | yes | SUCCESS | `username`, `old_role`, `new_role` | A role changed. The account's sessions end |
| `USER_DISABLED` | yes | SUCCESS | `username` | An account was disabled. Its sessions end |
| `USER_ENABLED` | | SUCCESS | `username` | An account was enabled again |
| `MFA_RESET` | yes | SUCCESS | `username` | An administrator removed an account's second factor. The user enrols again at the next sign-in |
| `MFA_REQUIREMENT_CHANGED` | yes | SUCCESS | `username`, `required` | The second factor was made optional or mandatory for a requester. Agents and administrators always need it |
| `PASSWORD_RESET_BY_ADMIN` | yes | SUCCESS | `username` | An administrator issued a temporary password. The user must replace it at the next sign-in |
| `USER_ERASED` | yes | SUCCESS | `username`, `tickets_deleted`, `tickets_unassigned` | The right to erasure (SR-10): personal data replaced and the user's tickets deleted. Earlier events keep the UUID and username, which the chain needs |

### Configuration (`CONFIG`): UC-06

| Event | Alert | Outcomes | Details | When |
|---|---|---|---|---|
| `CATEGORY_CREATED` | | SUCCESS | `name` | A ticket category was added |
| `CATEGORY_UPDATED` | | SUCCESS | `name`, `old_name`, `active` | A category was renamed, activated or deactivated |
| `RETENTION_CHANGED` | yes | SUCCESS | `old_months`, `new_months` | The retention period was changed. It cannot be set beyond the deployment's maximum |

### Tickets (`DATA`): UC-02 to UC-04, MU-04, MU-05

| Event | Alert | Outcomes | Details | When |
|---|---|---|---|---|
| `TICKET_CREATED` | | SUCCESS | `category` | A ticket was filed |
| `TICKET_UPDATED` | | SUCCESS | `fields`, `status`, `priority`, `assignee_id` | Status, priority, assignee or resolution changed. Only the names of the changed fields and the new enum values are recorded, never the resolution text |
| `COMMENT_ADDED` | | SUCCESS | `internal` | A comment or an internal note was added. Its text is never recorded |
| `ATTACHMENT_UPLOADED` | | SUCCESS | `ticket_id`, `media_type`, `size`, `scan` (`NOT_SCANNED` in the prototype) | A file passed inspection and was stored |
| `ATTACHMENT_DOWNLOADED` | | SUCCESS | `ticket_id` | An attachment was downloaded |
| `UPLOAD_REJECTED` | | FAILURE | `reason` (`type_not_allowed`, `extension_mismatch`, `active_content`, `malware`, `too_large`, `too_many`, `empty`, `unreadable`) | A file was refused. The file name is not recorded |

### Privacy (`PRIVACY`): SC-11

| Event | Alert | Outcomes | Details | When |
|---|---|---|---|---|
| `RETENTION_PURGE` | | SUCCESS | `closed_before`, `deleted` | The nightly job (03:15 UTC) deleted closed tickets past the retention period |

`USER_ERASED` (above) is also in this category.

### The audit trail itself (`AUDIT`): UC-07, MU-08

| Event | Alert | Outcomes | Details | When |
|---|---|---|---|---|
| `AUDIT_LOG_VIEWED` | | SUCCESS | `filter_category`, `filter_type`, `filter_actor`, `alert_only`, `page` | An administrator read the audit log. Reading the trail is itself recorded |
| `AUDIT_CHAIN_VERIFIED` | | SUCCESS | `checked_up_to` | The chain is intact up to this `seq`. The check runs two minutes after start-up, then every hour, and on demand from the audit page |
| `AUDIT_CHAIN_BROKEN` | yes | FAILURE | `broken_at`, `reason` ("content does not match its hash", "previous hash does not match", "missing sequence number", "rows removed from the end of the trail") | A row was altered, removed or inserted out of order |

### System (`SYSTEM`)

| Event | Alert | Outcomes | Details | When |
|---|---|---|---|---|
| `APP_STARTED` | | SUCCESS | `java` | The API started. This is also the deployment event of 5.2.3 C |
| `APP_STOPPING` | | SUCCESS | | The API is shutting down |
| `KEYS_ROTATED` | | SUCCESS | `pepper_key`, `password_records`, `recovery_records`, `totp_records`, `unreadable` | At start-up, records sealed under an older key were sealed again under the current one |
| `NOTIFICATION_SENT` | | SUCCESS | | A ticket-change mail was sent. The target is the ticket; the mail holds its number and a link only |
| `NOTIFICATION_FAILED` | | FAILURE | | The mail relay refused or could not be reached |

### Input (`INPUT`)

| Event | Alert | Outcomes | Details | When |
|---|---|---|---|---|
| `INPUT_VALIDATION_FAILED` | | FAILURE | `reason` (`body`, `parameter`, `unknown_field`, `unreadable_body`), `fields` or `field` | A request was refused by validation (400). For example, a requester who adds `"status"` to a ticket body gets `unknown_field` with `field: status`, which is the mass-assignment probe of T-07 |

## Detection rules for the blue team

These are the five rules of 5.2.3 C, written against the fields above. The `jq` lines run against the
collector's file; a SIEM rule selects on the same fields:

```sh
docker compose exec collector cat /var/log/securedesk/audit.jsonl | jq -c 'select(...)'
```

| # | Rule | Selection | Threshold |
|---|---|---|---|
| R1 | More than ten failed logins for one account in five minutes | `.event.event == "LOGIN_PASSWORD" and .event.outcome == "FAILURE"`, grouped by `.event.actor` (or by `src_ip` when the actor is `-`) | > 10 per 5 min. `ACCOUNT_LOCKED` fires at 10 in 15 min regardless |
| R2 | A burst of 403s in one session | `.event.category == "AUTHZ"`, grouped by `.event.session` | ≥ 5 per minute. `OBJECT_ACCESS_DENIED` with `not_permitted` is a strong signal of an IDOR probe |
| R3 | A role change outside office hours | `.event.event == "USER_ROLE_CHANGED"` and the hour of `.event.ts` (local time) outside 08–18 or on a weekend | any |
| R4 | An MFA reset followed by a login from a new IP | `MFA_RESET` with target X, then `LOGIN_COMPLETE` with `actor_id` X from a `src_ip` not seen for X in the previous 30 days | within 24 h |
| R5 | Any break in the hash chain | `.event.event == "AUDIT_CHAIN_BROKEN"`, or a gap in `seq` at the collector, or a `prev_hash` at the collector that does not equal the previous line's `hash` | any |

Every event with `alert: true` should page on its own, on top of these rules. The rules run on the
collector's copy. An attacker who controls the database can stop new rows being written, but cannot
recall the lines that already left the host.

The database check cannot see one attack: a row deleted and every later hash recomputed. Comparing
the `hash` values at the collector with the table catches it.

A `seq` gap at the collector has an innocent cause too. While the collector is unreachable, the API
holds up to 10,000 events. When that queue is full, the oldest are dropped from the queue (they stay
in the database), and the API logs a warning with the count. So treat a gap as an incident until the
warning explains it.
