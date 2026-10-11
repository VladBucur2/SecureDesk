# 0009. A hash-chained audit table plus an off-host copy

## Context

SC-09 (BoK 5.2.3 C) asks for an append-only audit trail, forwarded off-host within seconds, with
tampering detectable. MU-08 is an insider or intruder covering their tracks.

## Decision

- Every event is one row in `audit_event`. It gets an explicit `seq`, and its `entry_hash` is SHA-256
  over the previous row's hash and the event's canonical JSON. `AuditWriter` appends under a lock in its
  own transaction, so concurrent requests cannot fork the chain.
- The application's database account has `SELECT` and `INSERT` on the table and nothing else. The
  schema and grants are applied by a separate migrator account, in a one-shot container.
- An event about a change (outcome `SUCCESS`) is written when the change's transaction commits. If the
  change rolls back, the event is still written, but as a `FAILURE` with `rolled_back: true`: it was
  attempted, not done. Failures and denials are written
  at once, whatever happens to the transaction.
- Every event is also printed as one JSON line on stdout and sent as RFC 5424 syslog over TLS 1.3, with
  a client certificate, to an rsyslog collector in the monitoring zone. The collector accepts only the
  peer name `securedesk-api`.
- `AuditChainVerifier` checks the whole chain two minutes after start-up, every hour, and on demand, and
  records the result. A break is an alert event.

## Consequences

- An altered or removed row is detected. The demonstration is in `docs/demonstrations.md`.
- The chain detects tampering; it does not prevent it. Someone with root on the database host can stop
  new rows being written and can rebuild the chain after a deletion. The collector's copy limits that
  window, and comparing the two closes it for every event that was already forwarded.
- Erasure (SR-10) cannot touch the audit rows. They hold identifiers and outcomes, never ticket content,
  which is what makes a twelve-month audit retention defensible under the GDPR.
