package nl.fontys.securedesk.audit;

import org.springframework.data.domain.Limit;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

/**
 * Walks the hash chain from the first row to the last and reports the first place where it no
 * longer holds: a row whose own hash does not match its content (altered), a row whose previous
 * hash is not the hash of the row before it (a row removed or inserted), or a gap in the sequence.
 * It also compares the last row with the last event this process wrote, which catches rows cut
 * off the end of the table while the API is running.
 *
 * <p>Hash chaining detects tampering; it does not prevent it (BoK 5.2.3 C). The copy already
 * forwarded to the collector is what an attacker on this host cannot reach.
 */
@Component
public class AuditChainVerifier {

    private static final int BATCH = 500;

    public record Result(boolean intact, long checkedUpTo, long brokenAt, String reason) {
        static Result ok(long upTo) {
            return new Result(true, upTo, -1, "-");
        }

        static Result broken(long upTo, long at, String reason) {
            return new Result(false, upTo, at, reason);
        }
    }

    private final AuditEventRepository repository;
    private final AuditWriter writer;
    private final AuditLog audit;

    public AuditChainVerifier(AuditEventRepository repository, AuditWriter writer, AuditLog audit) {
        this.repository = repository;
        this.writer = writer;
        this.audit = audit;
    }

    public Result verify() {
        long writtenByThisProcess = writer.lastSeq();
        String previous = AuditEvent.GENESIS;
        long expectedSeq = 1;
        long last = 0;
        while (true) {
            List<AuditEvent> batch = repository.findBySeqGreaterThanOrderBySeqAsc(last, Limit.of(BATCH));
            if (batch.isEmpty()) {
                break;
            }
            for (AuditEvent event : batch) {
                if (event.getSeq() != expectedSeq) {
                    return Result.broken(last, expectedSeq, "missing sequence number");
                }
                if (!event.getPrevHash().equals(previous)) {
                    return Result.broken(last, event.getSeq(), "previous hash does not match");
                }
                if (!event.computeHash().equals(event.getEntryHash())) {
                    return Result.broken(last, event.getSeq(), "content does not match its hash");
                }
                previous = event.getEntryHash();
                last = event.getSeq();
                expectedSeq = last + 1;
            }
        }
        if (writtenByThisProcess > last) {
            return Result.broken(last, last + 1, "rows removed from the end of the trail");
        }
        return Result.ok(last);
    }

    /**
     * Verifies and records the result as an event of its own; a break carries the alert flag.
     * The actor is the administrator who asked, or "system" for the scheduled run.
     */
    public Result verifyAndRecord(boolean bySystem) {
        Result result = verify();
        AuditLog.Entry event = result.intact()
                ? audit.event(AuditType.AUDIT_CHAIN_VERIFIED).detail("checked_up_to", result.checkedUpTo())
                : audit.event(AuditType.AUDIT_CHAIN_BROKEN).outcome(Outcome.FAILURE)
                        .detail("broken_at", result.brokenAt()).detail("reason", result.reason());
        if (bySystem) {
            event.system();
        }
        event.write();
        return result;
    }

    @Scheduled(fixedDelayString = "${securedesk.audit.verify-interval:PT1H}",
               initialDelayString = "${securedesk.audit.verify-initial-delay:PT2M}")
    void scheduled() {
        verifyAndRecord(true);
    }

    Optional<AuditEvent> lastEvent() {
        return repository.findTopByOrderBySeqDesc();
    }
}
