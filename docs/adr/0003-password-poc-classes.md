# 0003. Argon2id through the password PoC's classes

## Context

BoK 6.3.7 planned to use Spring Security's `Argon2PasswordEncoder(16, 32, 1, 19456, 2)` in SecureDesk.
Building the prototype showed what that encoder cannot do:

- It cannot say why a check failed, so a tampered record and a wrong password look the same.
- It does not bound the parameters it reads back from storage. A record that asks for gigabytes of
  memory would turn one sign-in into a denial of service.
- It has no notion of the pepper of ADR 0002.

## Decision

SecureDesk uses the PoC's `Argon2id`, `StoredHash` and `PasswordPolicy` classes, ported with their tests.
They use the same Bouncy Castle primitive as Spring's encoder. `PasswordHasher` puts them together:
unseal, parse with bounds, verify in constant time, report `OK`, `OK_REHASHED`, `FAILED` or `TAMPERED`,
and re-hash when the stored parameters differ from the policy (m=19456 KiB, t=2, p=1). A semaphore
limits concurrent Argon2id computations, so a burst of sign-ins queues on virtual threads rather than
exhausting memory. An unknown username is verified against a dummy record with the same parameters, so
the response time does not reveal whether the account exists.

## Consequences

- The parameters, the policy and the blocklist are the PoC's, so the PoC's evidence (6.3.5) carries
  over.
- This is more code of our own than the plan, but the tests carried over with it:
  `Argon2idTest` (RFC 9106 vectors), `StoredHashTest` and `PasswordPolicyTest`.
