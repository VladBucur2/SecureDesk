# Architecture decision records

These are the decisions where the BoK report (chapters 5 and 6) left a choice open, or where building the
prototype changed what the report planned. Each record gives the context, the decision and its
consequences. A record is never edited after the fact; a later decision supersedes it.

| # | Decision | Status |
|---|---|---|
| [0001](0001-built-in-authentication.md) | Authentication is built into the API, not delegated to an identity provider | Accepted |
| [0002](0002-pepper-seals-the-hash-record.md) | The pepper encrypts the finished Argon2id record, and rotates by re-sealing | Accepted |
| [0003](0003-password-poc-classes.md) | Argon2id through the password PoC's classes, not Argon2PasswordEncoder | Accepted |
| [0004](0004-attachments-in-the-database.md) | Attachments are stored in MySQL, not in a MinIO object store | Accepted |
| [0005](0005-object-authorisation-in-the-service-layer.md) | Object-level authorisation in one service, not at the gateway (SbD AC-04 N-A) | Accepted |
| [0006](0006-server-side-sessions.md) | Opaque server-side sessions with a session-bound CSRF token, no JWT | Accepted |
| [0007](0007-secrets-as-mounted-files.md) | Secrets are mounted files until the vault of BoK 6.5 exists | Accepted |
| [0008](0008-spring-boot-4.md) | Spring Boot 4.1 on Java 21 | Accepted |
| [0009](0009-audit-trail-in-the-database-and-off-host.md) | The audit trail is a hash-chained table plus an off-host syslog copy | Accepted |
