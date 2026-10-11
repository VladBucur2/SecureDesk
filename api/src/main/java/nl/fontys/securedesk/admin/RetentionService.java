package nl.fontys.securedesk.admin;

import nl.fontys.securedesk.audit.AuditLog;
import nl.fontys.securedesk.audit.AuditType;
import nl.fontys.securedesk.common.ApiException;
import nl.fontys.securedesk.ticket.TicketErasure;
import nl.fontys.securedesk.ticket.TicketRepository;
import nl.fontys.securedesk.ticket.TicketStatus;
import org.springframework.data.domain.Limit;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

/**
 * UC-06 and SC-11. The retention period is a privacy control, so changing it is a security event
 * with the old and the new value and the alert flag; the daily purge is an event of its own.
 */
@Service
public class RetentionService {

    static final String KEY = "retention.closed_ticket_months";
    private static final int BATCH = 500;

    public record Retention(int months, int maxMonths) {
    }

    private final AppSettingRepository settings;
    private final TicketRepository tickets;
    private final TicketErasure erasure;
    private final RetentionProperties properties;
    private final AuditLog audit;
    private final Clock clock;

    public RetentionService(AppSettingRepository settings, TicketRepository tickets, TicketErasure erasure,
                            RetentionProperties properties, AuditLog audit, Clock clock) {
        this.settings = settings;
        this.tickets = tickets;
        this.erasure = erasure;
        this.properties = properties;
        this.audit = audit;
        this.clock = clock;
    }

    public Retention current() {
        int months = settings.findById(KEY).map(s -> Integer.parseInt(s.getValue()))
                .orElse(properties.defaultMonths());
        return new Retention(Math.min(months, properties.maxMonths()), properties.maxMonths());
    }

    @Transactional
    public Retention change(int months) {
        if (months < 1 || months > properties.maxMonths()) {
            throw ApiException.badRequest("out_of_range",
                    "The retention period is between 1 and " + properties.maxMonths() + " months.");
        }
        int old = current().months();
        Instant now = clock.instant();
        AppSetting setting = settings.findById(KEY).orElseGet(() -> new AppSetting(KEY, String.valueOf(months), now));
        setting.setValue(String.valueOf(months), now);
        settings.save(setting);
        audit.event(AuditType.RETENTION_CHANGED).target("setting", KEY)
                .detail("old_months", old).detail("new_months", months).write();
        return current();
    }

    /** Deletes closed tickets older than the period. Called daily and on demand by an administrator. */
    public int purge(boolean bySystem) {
        Instant cutoff = clock.instant().atZone(ZoneOffset.UTC).minusMonths(current().months()).toInstant();
        int deleted = 0;
        while (true) {
            List<UUID> batch = tickets.findIdsClosedBefore(TicketStatus.CLOSED, cutoff, Limit.of(BATCH));
            if (batch.isEmpty()) {
                break;
            }
            deleted += erasure.delete(batch);
            if (batch.size() < BATCH) {
                break;
            }
        }
        AuditLog.Entry event = audit.event(AuditType.RETENTION_PURGE)
                .detail("deleted", deleted).detail("closed_before", cutoff);
        if (bySystem) {
            event.system();
        }
        event.write();
        return deleted;
    }

    @Scheduled(cron = "${securedesk.retention.cron:0 15 3 * * *}", zone = "UTC")
    void daily() {
        purge(true);
    }
}
