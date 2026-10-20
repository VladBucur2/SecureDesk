# Architecture decision records

These records document the prototype's main design decisions. Some write up a decision the BoK report
had already made; others are choices the prototype made where the report left one open, or where it
departs from the report. The Origin column says which. Each record gives the context, the decision and its
consequences. A record is never edited after the fact; a later decision supersedes it.

| # | Decision | Origin | Status |
|---|---|---|---|
| [0001](0001-built-in-authentication.md) | Authentication is built into the API, not delegated to an identity provider | Report, 5.2.3 A | Accepted |
| [0002](0002-pepper-seals-the-hash-record.md) | The pepper encrypts the finished Argon2id record, and rotates by re-sealing | Report, 5.2.3 A and 6.3.7 | Accepted |
| [0003](0003-password-poc-classes.md) | Argon2id through the password PoC's classes, not Argon2PasswordEncoder | Prototype; departs from 5.2.3 A, 6.1.2 and 6.3.7 | Accepted |
| [0004](0004-attachments-in-the-database.md) | Attachments are stored in MySQL, not in a MinIO object store | Prototype; departs from 2.3 and SC-05 | Accepted |
| [0005](0005-object-authorisation-in-the-service-layer.md) | Object-level authorisation in one service, not at the gateway (SbD AC-04 N-A) | Report, 5.2.3 B | Accepted |
| [0006](0006-server-side-sessions.md) | Opaque server-side sessions with a session-bound CSRF token, no JWT | Report, SC-01; details from the prototype | Accepted |
| [0007](0007-secrets-as-mounted-files.md) | Secrets are mounted files until the vault of BoK 6.5 exists | Prototype; departs from SC-07 | Accepted |
| [0008](0008-spring-boot-4.md) | Spring Boot 4.1 on Java 21 | Prototype; departs from 6.1.2 | Accepted |
| [0009](0009-audit-trail-in-the-database-and-off-host.md) | The audit trail is a hash-chained table plus an off-host syslog copy | Report, 5.2.3 C; details from the prototype | Accepted |
