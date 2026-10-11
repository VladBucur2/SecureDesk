# 0007. Secrets are mounted files until the vault exists

## Context

SC-07 puts every secret in a vault in the management zone, retrieved at runtime with short-lived
credentials. Key management and secrets handling is BoK topic 6.5, which is not written yet. The
laboratory runs on one host with Docker Compose.

## Decision

`docker compose run --rm setup` generates every secret once, under `./secrets/` (git-ignored). The script
is `deploy/setup/setup.sh`. Each service mounts only its own directory, read-only:

- the internal EC P-256 CA and one certificate per hop;
- the database passwords: root, migrator and app;
- the pepper and TOTP keys;
- the bootstrap passwords.

The API reads its secrets as a Spring config tree (`/run/secrets/config/<property name>`). Nothing secret
is in the images, in `docker-compose.yml`, in an `.env` file or in the code. The CA's private key is
never mounted into a container.

## Consequences

- A host compromise exposes the secrets. That is already the accepted residual risk of the single-host
  laboratory (BoK 5.2.6).
- No credential is short-lived. The database passwords are static, and the key files rotate only by the
  procedure of ADR 0002.
- Replacing the files with a vault agent that renders the same paths changes no application code.
