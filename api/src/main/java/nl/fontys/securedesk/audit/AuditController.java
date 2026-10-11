package nl.fontys.securedesk.audit;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;
import nl.fontys.securedesk.common.PageResponse;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;

/**
 * UC-07: the administrator's view of the audit trail. Reading it is itself an audited action.
 * There is no endpoint that changes or removes an entry, and the database would refuse one anyway.
 * Entries are returned as data and escaped by the front end, so an injected string cannot run in
 * the administrator's browser.
 */
@RestController
@RequestMapping("/api/admin/audit")
public class AuditController {

    public record EntryView(long seq, String eventId, Instant ts, String event, String category, String outcome,
                            boolean alert, String actorId, String actor, String actorRole, String srcIp,
                            String session, String targetType, String targetId, String correlationId,
                            String details, String hash) {

        static EntryView of(AuditEvent e) {
            return new EntryView(e.getSeq(), e.getEventId(), e.getTs(), e.getEventType(), e.getCategory(),
                    e.getOutcome(), e.isAlert(), e.getActorId(), e.getActor(), e.getActorRole(), e.getSrcIp(),
                    e.getSessionHash(), e.getTargetType(), e.getTargetId(), e.getCorrelationId(), e.getDetails(),
                    e.getEntryHash());
        }
    }

    public record TypeView(String name, String category, boolean alert, String purpose) {
    }

    private final AuditQueries queries;
    private final AuditChainVerifier verifier;

    public AuditController(AuditQueries queries, AuditChainVerifier verifier) {
        this.queries = queries;
        this.verifier = verifier;
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public PageResponse<EntryView> search(
            @RequestParam(required = false) @Pattern(regexp = "[A-Z_]{1,40}") String type,
            @RequestParam(required = false) @Pattern(regexp = "[A-Z]{1,16}") String category,
            @RequestParam(required = false) @Pattern(regexp = "[a-z0-9._-]{1,64}") String actor,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @RequestParam(defaultValue = "false") boolean alertOnly,
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "50") @Min(1) @Max(PageResponse.MAX_SIZE) int size) {
        return PageResponse.of(queries.search(new AuditQueries.Filter(type, category, actor, from, to, alertOnly),
                page, size), EntryView::of);
    }

    /** The event catalogue, for the filter and for anyone who wants to know what each event means. */
    @GetMapping("/types")
    @PreAuthorize("hasRole('ADMIN')")
    public List<TypeView> types() {
        return Arrays.stream(AuditType.values())
                .map(t -> new TypeView(t.name(), t.category().name(), t.alert(), t.purpose())).toList();
    }

    /** Verifies the hash chain now; the result is recorded as an event like the hourly check. */
    @PostMapping("/verify")
    @PreAuthorize("hasRole('ADMIN')")
    public AuditChainVerifier.Result verify() {
        return verifier.verifyAndRecord(false);
    }
}
