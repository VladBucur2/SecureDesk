package nl.fontys.securedesk.audit;

import java.time.Instant;

/** An audit event before it has a place in the chain. */
record AuditRecord(
        String eventId,
        Instant ts,
        AuditType type,
        Outcome outcome,
        boolean alert,
        String actorId,
        String actor,
        String actorRole,
        String srcIp,
        String sessionHash,
        String targetType,
        String targetId,
        String correlationId,
        AuditDetails details) {

    /** The same event for an action whose transaction rolled back: it was attempted, not done. */
    AuditRecord rolledBack() {
        AuditDetails copy = new AuditDetails();
        details.asMap().forEach(copy::put);
        copy.put("rolled_back", "true");
        return new AuditRecord(eventId, ts, type, outcome == Outcome.SUCCESS ? Outcome.FAILURE : outcome,
                alert, actorId, actor, actorRole, srcIp, sessionHash, targetType, targetId, correlationId, copy);
    }
}
