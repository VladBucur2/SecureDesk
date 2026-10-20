# 0008. Spring Boot 4.1 on Java 21

## Context

The report plans Spring Boot 3 for SecureDesk, the same stack as the mfa-poc (6.1.2: "Identical, so the
code transfers"). The 3.x line ended with 3.5, whose open-source support ended in June 2026. A product that falls under the CRA must ship with security updates for its support
period (Annex I Part II).

## Decision

The API uses Spring Boot 4.1. That brings Spring Framework 7, Spring Security 7, Hibernate 7, Jackson 3
and Tomcat 11, on Java 21 with virtual threads. Versions outside Boot's dependency management are pinned
in `api/pom.xml`: Bouncy Castle, ZXing, ArchUnit and the CycloneDX plugin. Dependabot proposes updates
for Maven, npm, the Docker base images and the GitHub Actions. The actions are pinned by commit SHA.

## Consequences

- Virtual threads let the progressive login delay and the Argon2id queue wait without holding a platform
  thread. Blocking code avoids `synchronized` (see `AuditWriter`).
- Some Spring Security test helpers behave differently in 7.x. For example, `csrf()` replaces the CSRF
  repository, so the tests place a token in the real session instead (`support/Sessions`).
