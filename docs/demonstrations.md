# Demonstrations

These are commands and walk-throughs that show the controls working in the running laboratory. Every
command below was run against the stack started with `docker compose up -d --build`; the output shown
is what it printed. Run them from the repository root.

## 0. Start the laboratory

```sh
docker compose run --rm setup      # once: ./secrets with the CA, certificates, keys and passwords
docker compose up -d --build       # migrate runs once, then api, web, mysql, collector and mail
docker compose ps
```

The setup prints the first administrator's password and the demo password. They are also kept in
`secrets/api/config/securedesk.bootstrap.admin-password` and `secrets/api/config/securedesk.demo.password`.
Trust `secrets/ca/ca.crt` in the browser (or the operating system), then open
<https://securedesk.localhost:8443>.

## 1. Sign-in, enrolment and roles (SC-01, SC-02, SC-03)

This is the browser walk-through. A Playwright script ran it end to end with 14 checks, no failures
and no CSP violations.

1. Sign in as `admin` with the bootstrap password. You are sent to **Choose a new password**.
   - `admin password 1` is refused: it contains the username.
   - `Password1!` is refused: it is shorter than 15 characters.
   - A long passphrase is accepted.
2. **Turn on the second factor**: scan the QR code, or type the key, into an authenticator app and enter
   the code. Ten recovery codes are shown once.
3. In **Users**, create an account. A temporary password is shown once. The new user must replace it,
   then enrol, at their first sign-in.
4. Sign in as `alice` (a requester, demo password), enrol, and open *My laptop won't boot*.
   - The agent's reply is visible; the internal note about SMART errors is not, and it is not in the
     response either (look in the browser's network tab).
   - File a ticket with `outlook.log` and `invoice.pdf.exe`. The log is attached; the executable is
     refused.
   - In the console, `fetch('/api/queue').then(r => r.status)` gives `403`.
5. Sign in as `carol` (an agent): the queue, an internal note, status and assignment.
6. Sign in as `bob`. He is a requester whose second factor is optional in the demo data, so the password
   alone signs him in.
7. Sign in as `admin` again. The second factor is now required. In **Audit log**, filter on category
   `AUTHZ` to see Alice's and Bob's refused calls. **Verify hash chain** says the chain is intact.

Try a wrong password ten times for one account and watch the delays grow (0, 1, 2, 4, 8 s). After the
tenth failure the account is locked for fifteen minutes, and the response is the same generic failure
throughout.

## 2. TLS and headers at the edge (SC-04, SC-12)

```console
$ curl -sS --cacert secrets/ca/ca.crt -o /dev/null -D - https://securedesk.localhost:8443/
HTTP/2 200
strict-transport-security: max-age=31536000
content-security-policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests
x-frame-options: DENY
referrer-policy: no-referrer
...

$ curl -sS --cacert secrets/ca/ca.crt --tls-max 1.2 https://securedesk.localhost:8443/
curl: (35) OpenSSL/3.0.13: error:0A00042E:SSL routines::tlsv1 alert protocol version

$ curl -sS --cacert secrets/ca/ca.crt -o /dev/null -w "%{http_code}\n" https://securedesk.localhost:8443/actuator/health
404
```

## 3. Rate limiting and CSRF on the sign-in (SC-02, SC-04)

Fifteen sign-in posts in a row, without the CSRF token that `GET /api/auth/session` hands out:

```console
$ for i in $(seq 1 15); do curl -s --cacert secrets/ca/ca.crt -o /dev/null -w "%{http_code}\n" \
    -X POST -H 'Content-Type: application/json' -d '{"username":"nobody","password":"x"}' \
    https://securedesk.localhost:8443/api/auth/login; done | sort | uniq -c
     11 403
      4 429
```

The first eleven reach the API and are refused for the missing token (`CSRF_DENIED` in the audit log).
After that, Nginx's limit (20 per minute, burst 10) answers `429` without the API seeing the request.

## 4. Only Nginx can talk to the API (SC-12, mutual TLS)

The API listens on the internal `app` network only and requires a client certificate. Run these from a
throw-away container on that network; the setup image has `openssl`:

```console
$ docker run --rm --network securedesk_app -v "$PWD/secrets/nginx/tls:/tls:ro" --entrypoint sh securedesk-setup:0.1.0 -c \
  'printf "GET /api/auth/session HTTP/1.1\r\nHost: api\r\nConnection: close\r\n\r\n" | openssl s_client -quiet -connect api:8443 -CAfile /tls/ca.crt -verify_hostname api'
... ssl3_read_bytes:tlsv13 alert certificate required ... SSL alert number 116

$ docker run --rm --network securedesk_app -v "$PWD/secrets/nginx/tls:/tls:ro" --entrypoint sh securedesk-setup:0.1.0 -c \
  'printf "GET /api/auth/session HTTP/1.1\r\nHost: api\r\nConnection: close\r\n\r\n" | openssl s_client -quiet -connect api:8443 -CAfile /tls/ca.crt -verify_hostname api -cert /tls/client.crt -key /tls/client.key 2>/dev/null | grep -E "^HTTP/"'
HTTP/1.1 200
```

## 5. The database account cannot rewrite history (SC-06, SC-09)

```console
$ docker compose exec mysql sh -c 'mysql -h mysql --ssl-mode=VERIFY_IDENTITY --ssl-ca=/run/secrets/tls/ca.crt \
    -usecuredesk_app -p"$(cat /run/secrets/app-password)" securedesk -e "UPDATE audit_event SET outcome=\"SUCCESS\" WHERE seq=1"'
ERROR 1142 (42000) at line 1: UPDATE command denied to user 'securedesk_app'@'172.19.0.2' for table 'audit_event'

$ docker compose exec mysql sh -c 'mysql -h mysql --ssl-mode=DISABLED -usecuredesk_app -p"$(cat /run/secrets/app-password)" securedesk -e "SELECT 1"'
ERROR 1045 (28000): Access denied for user 'securedesk_app'@'172.19.0.2' (using password: YES)

$ docker compose exec mysql sh -c 'mysql -uroot -p"$(cat /run/secrets/root-password)" -e "SHOW GRANTS FOR securedesk_app"'
GRANT SELECT, INSERT ON `securedesk`.`audit_event` TO `securedesk_app`@`%`
...
```

The second command shows that a connection without TLS is refused: the account is `REQUIRE SSL`, and
the server has `require_secure_transport=ON`.

## 6. Tampering with the audit trail is detected and already off-host (SC-09, MU-08)

This plays an attacker with root on the database host who rewrites the first event. It turns the
bootstrap administrator's role into a requester's.

```console
$ docker compose exec mysql sh -c 'mysql -uroot -p"$(cat /run/secrets/root-password)" securedesk \
    -e "UPDATE audit_event SET details=REPLACE(details, \"ADMIN\", \"REQUESTER\") WHERE seq=1"'
$ docker compose restart api      # or press "Verify hash chain" on the audit page
```

The verifier runs two minutes after start-up. The collector then holds:

```json
{"received":"2026-10-11T09:56:02.834281+00:00","from":"172.23.0.3","hostname":"securedesk-api",
 "msgid":"AUDIT_CHAIN_BROKEN","event":{"seq":"51","event":"AUDIT_CHAIN_BROKEN","category":"AUDIT",
 "outcome":"FAILURE","alert":true,"actor":"system","actor_role":"SYSTEM",
 "details":{"broken_at":"1","reason":"content does not match its hash"}, "...": "..."}}
```

```sh
docker compose exec collector grep AUDIT_CHAIN_BROKEN /var/log/securedesk/audit.jsonl
```

The collector also still has the original `USER_CREATED` line for `seq` 1, with `"role":"ADMIN"`. The
attacker cannot reach it. Put the row back with the reverse `REPLACE` and the next verification is
intact again.

## 7. The collector accepts only the API (SC-09, SC-12)

```console
$ docker run --rm --network securedesk_monitoring -v "$PWD/secrets/collector/tls:/tls:ro" --entrypoint sh securedesk-setup:0.1.0 -c \
  'echo "<134>1 2026-10-11T10:00:00Z forged app - - - hello" | openssl s_client -quiet -connect collector:6514 -CAfile /tls/ca.crt'
read:errno=104

$ docker compose logs collector | grep "not permitted"
rsyslogd: peer ... did not provide a certificate, not permitted to talk to it
```

A certificate from the same CA with another name is refused as well ("peer name not authorized"),
because the collector only accepts `securedesk-api`.

## 8. What a notification contains (SC-11, MU-13)

Open <http://127.0.0.1:8025> (Mailpit, the stand-in for the customer's mail relay), or:

```console
$ curl -s http://127.0.0.1:8025/api/v1/messages | jq -r '.messages[] | .To[0].Address + " | " + .Subject + " | " + .Snippet'
alice@securedesk.localhost | [SecureDesk] Ticket SD-9891EC05 was updated | Your ticket SD-9891EC05 was updated. Sign in to see what changed: https://securedesk.localhost:8443/tickets/9891ec05-… This message co…
```

The mail has the ticket number and a link, and none of the content. The address comes from the
user record. The API only sends mail over STARTTLS and checks the relay's certificate.

## 9. The test suite

```sh
cd api && mvn -B verify            # or: docker compose run --rm test
```

The suite has 259 tests. These are the ones that matter most for the BoK:

| Test | Shows |
|---|---|
| `authz/AuthorizationMatrixTest` | 151 cases: every role against every endpoint, own and someone else's object |
| `auth/AuthenticationFlowTest` | The mfa-poc's test cases, identical answers for unknown users, lockout and delays, replay, fixation, step-up, session revocation, rehash and tampering |
| `crypto/*Test` | The password PoC's tests, plus the pepper's rehash, tamper and rotation cases |
| `audit/AuditTrailTest` | Chain, altered and removed rows, rolled-back changes |
| `audit/LogHygieneTest` | Marker passwords, codes and ticket text never reach any log stream |
| `ArchitectureTest` | No repository in a controller, `@PreAuthorize` everywhere, step-up on admin changes, no entity over the wire |
