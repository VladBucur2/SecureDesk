# SecureDesk

SecureDesk is a ticketing and helpdesk system for small and medium organisations. Employees file
tickets, agents work a queue, and administrators manage accounts, categories, retention and the audit
trail. This repository is the prototype for the Body of Knowledge report. It implements the security
design of chapter 5 (controls SC-01 to SC-12, with SC-01/02, SC-03 and SC-09 worked out in 5.2.3) and the
logging design of 5.3. It builds on two proofs of concept from chapter 6:

- **Authentication:** the two-step sign-in and TOTP of the [mfa-poc](https://github.com/VladBucur2/mfa-poc).
- **Password storage:** the Argon2id, stored-hash format, password policy and blocklist of the
  password-storage PoC, with the pepper used as an AES-256-GCM seal (6.3.7).

> This is a laboratory prototype. It runs on one host with Docker Compose, generates its own CA, and
> leaves out the parts of the reference architecture that need infrastructure of their own: the
> secrets vault, the bastion, backups and image signing. [docs/security-controls.md](docs/security-controls.md)
> lists what is in place and what is not.

## Architecture

```
                 browser
                    │ HTTPS, TLS 1.3, HTTP/2           127.0.0.1:8443 only
 ┌── dmz ───────────▼──────────────────────────┐
 │ web: Nginx + React build                     │  CSP, HSTS, rate limits, body-size limits
 └──────────────────┬──────────────────────────┘
                    │ mutual TLS (Nginx's client certificate)
 ┌── app ───────────▼──────────────────────────┐
 │ api: Spring Boot 4.1, Java 21                │  sessions, TOTP, Argon2id + pepper,
 └───┬────────────────────┬─────────────┬──────┘  authorisation, audit trail
     │ TLS 1.3            │ syslog/TLS  │ SMTP + STARTTLS
 ┌── data ─────▼──┐ ┌── monitoring ─▼─┐ ┌── mail ─▼─────────────┐
 │ mysql 8.4      │ │ collector       │ │ mail (Mailpit)         │
 │ migrate (once) │ │ rsyslog         │ │ UI on 127.0.0.1:8025   │
 └────────────────┘ └─────────────────┘ └────────────────────────┘
```

The zones are Docker networks. `app`, `data`, `monitoring` and `mail` are internal, so nothing in
them can reach the internet. Each hop uses TLS with certificates from an internal CA that
`docker compose run --rm setup` creates. The schema and grants are applied by a one-shot `migrate`
container with its own database account. The running API's account has no DDL rights and only
`SELECT, INSERT` on the audit table.

## Quick start

You need Docker with Compose v2.

```sh
docker compose run --rm setup     # once: CA, certificates, keys and passwords in ./secrets (git-ignored)
docker compose up -d --build      # builds and runs the API's tests, then starts everything
```

The setup prints the passwords. They are also in `secrets/api/config/`.

1. Import `secrets/ca/ca.crt` into your browser's or system's trust store.
2. Open <https://securedesk.localhost:8443>. `*.localhost` resolves to the loopback address in
   current browsers.

| Account | Role | First sign-in |
|---|---|---|
| `admin` | Administrator | Bootstrap password. Choose a new password, then enrol TOTP |
| `alice` | Requester | Demo password, then enrol TOTP |
| `bob` | Requester | Demo password only. His second factor is optional in the demo data |
| `carol`, `dave` | Agents | Demo password, then enrol TOTP |

Any authenticator app works: Google Authenticator, Microsoft Authenticator, Aegis, 1Password, and so
on. The enrolment page also shows the key as text.

The demo accounts and tickets exist because `SECUREDESK_DEMO_ENABLED=true` is set in
`docker-compose.yml`. Remove it for a clean installation that has only the administrator.

Other useful commands:

```sh
docker compose logs -f api                 # application log and the audit stream, JSON lines
docker compose exec collector tail -f /var/log/securedesk/audit.jsonl   # the off-host copy
docker compose run --rm test               # the API's test suite in a container
docker compose down                        # stop; add -v to also delete the database
```

The notification mails are at <http://127.0.0.1:8025>.

## Documentation

| Document | Contents |
|---|---|
| [docs/security-controls.md](docs/security-controls.md) | SC-01 to SC-12 and MU-01 to MU-13: where each control lives, what proves it, and what is left |
| [docs/event-catalogue.md](docs/event-catalogue.md) | The event catalogue of BoK 5.3.5: every audit event, its fields, and the blue team's detection rules |
| [docs/demonstrations.md](docs/demonstrations.md) | Commands and walk-throughs that show the controls in the running laboratory |
| [docs/adr/](docs/adr/README.md) | Architecture decision records: where the prototype decides what the report left open, or deviates from it |

## Repository layout

```
api/                     Spring Boot API (Maven)
  src/main/java/nl/fontys/securedesk/
    auth/                sign-in, TOTP, recovery codes, lockout, sessions, step-up      SC-01, SC-02
    crypto/              Argon2id, stored-hash format, password policy, pepper, keys    SC-02, SC-06
    ticket/              tickets, comments, attachments, TicketAccessService            SC-03, SC-05
    user/, admin/        accounts, roles, categories, retention, erasure                SC-03, SC-11
    audit/               event catalogue, hash chain, verifier, syslog forwarder        SC-09
    config/, common/     security configuration, error handling, input clean-up         SC-04
    migrate/             the one-shot schema migration (Flyway)                         SC-06
  src/main/resources/db/ schema (V1__schema.sql) and the application account's grants
web/                     React 19 + TypeScript (Vite), and the Nginx configuration of the DMZ
deploy/                  setup script, MySQL configuration and accounts, rsyslog collector
.github/                 CI (tests, npm audit, SBOMs, image build) and Dependabot
```

## Tests

```sh
cd api && mvn -B verify      # 259 tests, plus the SBOM; needs JDK 21 and nothing else (H2 in MySQL mode)
cd web && npm ci && npm run build
```

The suite includes:

- the authorisation matrix: every role against every endpoint, for own and other objects;
- the mfa-poc's authentication cases and the password PoC's tests;
- ArchUnit rules: no repository in a controller, `@PreAuthorize` on every handler, step-up on
  administrative changes;
- the audit chain and tampering tests;
- a log-hygiene test that searches every log stream for marker secrets.

## Deviations from the BoK report

Most of these have an [ADR](docs/adr/README.md):

- **Password minimum is 15 characters**, as concluded in 6.3.7, not the twelve of 5.2.3 A. The two
  sections of the report disagree; the prototype follows the later one.
- **Argon2id through the PoC's classes** rather than Spring Security's `Argon2PasswordEncoder`. The PoC's
  classes can tell a tampered record from a wrong password, and they bound the parameters they read
  back. The parameters are the same: m=19456 KiB, t=2, p=1 (ADR 0003).
- **Attachments are stored in MySQL**, not MinIO. MinIO no longer publishes community images, and the
  last published one would ship unpatched (ADR 0004).
- **Secrets are mounted files**, generated by the setup step, until the vault of BoK 6.5 exists
  (ADR 0007).
- **Spring Boot 4.1** instead of the Spring Boot 3 of 6.1.2, because 3.5's open-source support has ended
  (ADR 0008).
- **The collector runs on Ubuntu's rsyslog and the setup step on the JRE image**, not on Alpine, so the
  laboratory builds without extra package mirrors.

## Known limitations

These include the three residual risks of BoK 5.2.6 (malware scanning, one instance, one host), and
parts of the design that the laboratory does not build:

- **Malware scanning is a stub.** Uploads are checked by content, extension and active PDF content,
  and the scan result is recorded as `NOT_SCANNED`.
- **One instance on one host.** Sessions are in memory, there is no failover and no backups, and the
  zones share a host.
- **No backups and no volume encryption.** Only the credential records and TOTP secrets are encrypted at
  rest (SC-06).
- **No management zone.** The bastion, the vault and the CI/CD runner of 2.3 are not built. The fifth
  network is the mail relay's instead.
- **No SIEM.** Events reach an rsyslog collector that writes JSON lines. The alert flag and the
  detection rules of 5.2.3 C are documented in [docs/event-catalogue.md](docs/event-catalogue.md), but
  nothing runs the rules or raises alerts.
- **CI is incomplete.** It runs the tests, `npm audit`, the SBOMs and Dependabot. It does not sign or
  scan images, scan Maven dependencies or secrets, run the Schemathesis and ZAP runs of 5.2.3 A, or
  deploy (UC-09, SC-07, SC-08).
- **Some planned checks are manual or missing.** The timing comparison of 5.2.3 A is not automated.
  Cases 10 and 11 of the mfa-poc (the TLS captures) are not repeated. The rate limit is a manual
  demonstration ([docs/demonstrations.md](docs/demonstrations.md)).
- **TOTP can be phished in real time.** WebAuthn is the next step.
