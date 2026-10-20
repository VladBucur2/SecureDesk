# 0002. The pepper encrypts the finished hash record

## Context

This decision is the report's own; this record documents how the prototype carries it out. The pepper
was first planned as an HMAC over the password before hashing, rotated by re-hashing at each user's next
login. The password-storage PoC (BoK 6.3) showed that this rotation never finishes for users who do not
sign in, so the old key could never be destroyed. 6.3.7 therefore changed the design to the one that
5.2.3 A now describes. NIST SP 800-63B recommends a secret key
held apart from the hashes. OWASP notes that a pepper cannot be changed without the users' passwords.

## Decision

As in the PoC (6.3.7), the complete Argon2id record (`$argon2id$v=19$m=19456,t=2,p=1$salt$hash`) is
encrypted with AES-256-GCM under a key held outside the database (`Pepper`, `SealedBox`). The stored form
is `pepper:<key id>:<base64 of nonce, ciphertext and tag>` (`totp:` for TOTP secrets). The associated data binds the record to its owner
and purpose: `password:<user id>`, `recovery:<code id>`, `totp:<user id>`. The user id is the immutable
UUID, so a rename does not break the record.

Rotation: add a key under a new id, make it current, and restart. At start-up `KeyRotation` re-seals
every record that is still under an older key, without any password, and records `KEYS_ROTATED` with the
counts. After that the old key can be destroyed.

## Consequences

- A database dump without the key file cannot be attacked offline. A record copied into another user's
  row fails its GCM check: the user gets the generic failure, and `CREDENTIAL_TAMPERED` (an alert) is
  recorded.
- The TOTP secrets use the same construction under a separate key (SC-06, column-level encryption).
- Losing the key makes every password unusable. The key is therefore a backup item of its own, kept apart
  from the database backups. Losing it means an administrator issues new passwords, starting with
  the bootstrap account.
