# 0005. Object-level authorisation in one service

## Context

SbD AC-04 asks for authorisation centralised at the gateway or service mesh, as policy-as-code. That item
is written for many services behind a shared entry point. SecureDesk is one application, and its gateway
(Nginx) has no view of ticket ownership (BoK 5.2.3 B).

## Decision

AC-04 is answered N-A with this justification. Authorisation has two layers:

1. Function level: Spring Security denies every URL that is not explicitly permitted, and every handler
   carries `@PreAuthorize`. The `ArchitectureTest` fails the build if a handler lacks one, or if an
   `Admin*` controller method that changes something lacks `@RequiresRecentAuthentication`.
2. Object level: every ticket, comment and attachment is reached through `TicketAccessService`. It uses
   scoped finders (`findByIdAndRequesterId` for requesters) and returns 404 on a miss. The principal
   always comes from the session, never from the request. `ArchitectureTest` fails the build if a
   controller uses a repository.

Requester and agent DTOs are separate types. Unknown JSON fields are an error, so `status` or
`assigneeId` in a requester's body is refused (400) and recorded as `INPUT_VALIDATION_FAILED`.

## Consequences

- `AuthorizationMatrixTest` runs every role against every endpoint, for an own object and for someone
  else's. It also fails when an endpoint is added without a row in the matrix.
- The check still depends on convention inside the service layer. A new service method that skips
  `TicketAccessService` would compile. The red team is asked to probe object-level access specifically.
