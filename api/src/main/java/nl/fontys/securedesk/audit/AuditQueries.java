package nl.fontys.securedesk.audit;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.time.Instant;

/** Reading the audit trail (UC-07). Every read is itself recorded, with the filter that was used. */
@Service
public class AuditQueries {

    public record Filter(String type, String category, String actor, Instant from, Instant to, boolean alertOnly) {
    }

    private final AuditEventRepository repository;
    private final AuditLog audit;

    public AuditQueries(AuditEventRepository repository, AuditLog audit) {
        this.repository = repository;
        this.audit = audit;
    }

    public Page<AuditEvent> search(Filter filter, int page, int size) {
        audit.event(AuditType.AUDIT_LOG_VIEWED)
                .detail("filter_type", orDash(filter.type()))
                .detail("filter_category", orDash(filter.category()))
                .detail("filter_actor", orDash(filter.actor()))
                .detail("alert_only", filter.alertOnly())
                .detail("page", page).write();
        return repository.search(filter.type(), filter.category(), filter.actor(), filter.from(), filter.to(),
                filter.alertOnly(), PageRequest.of(page, size));
    }

    private static String orDash(String value) {
        return value == null ? "-" : value;
    }
}
