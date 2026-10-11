package nl.fontys.securedesk.ticket;

import nl.fontys.securedesk.admin.RetentionService;
import nl.fontys.securedesk.audit.AuditEvent;
import nl.fontys.securedesk.audit.AuditType;
import nl.fontys.securedesk.common.ApiException;
import nl.fontys.securedesk.support.IntegrationTest;
import nl.fontys.securedesk.user.AppUser;
import nl.fontys.securedesk.user.Role;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** SR-10 and SC-11: the retention period is bounded, and closed tickets past it are deleted with everything attached. */
class RetentionTest extends IntegrationTest {

    @Autowired
    RetentionService retention;
    @Autowired
    TicketRepository tickets;
    @Autowired
    TicketCommentRepository comments;
    @Autowired
    AttachmentRepository attachments;
    @Autowired
    AttachmentContentRepository contents;

    @Test
    @DisplayName("the period cannot be set beyond the configured maximum")
    void boundedPeriod() {
        assertThatThrownBy(() -> retention.change(61)).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> retention.change(0)).isInstanceOf(ApiException.class);
        assertThat(retention.change(12).months()).isEqualTo(12);
        assertThat(events(AuditType.RETENTION_CHANGED)).last().matches(AuditEvent::isAlert)
                .extracting(AuditEvent::getDetails).asString().contains("\"new_months\":\"12\"");
        retention.change(24);
    }

    @Test
    @DisplayName("closed tickets older than the period are deleted with comments and attachments; others stay")
    void purge() {
        AppUser requester = createUser("ret", Role.REQUESTER, false);
        Instant longAgo = clock.instant().atZone(ZoneOffset.UTC).minusMonths(30).toInstant();

        Ticket old = new Ticket(requester.getId(), 1L, "Old", "Closed long ago", longAgo);
        old.changeStatus(TicketStatus.CLOSED, longAgo);
        tickets.save(old);
        comments.save(new TicketComment(old.getId(), requester.getId(), "thanks", false, longAgo));
        Attachment file = attachments.save(new Attachment(old.getId(), requester.getId(), "a.txt", "text/plain", 1,
                "0".repeat(64), longAgo));
        contents.save(new AttachmentContent(file.getId(), "a".getBytes(StandardCharsets.UTF_8)));

        Ticket openOld = tickets.save(new Ticket(requester.getId(), 1L, "Still open", "Old but open", longAgo));
        Ticket recent = new Ticket(requester.getId(), 1L, "Recent", "Closed last week", clock.instant());
        recent.changeStatus(TicketStatus.CLOSED, clock.instant());
        tickets.save(recent);

        int deleted = retention.purge(true);

        assertThat(deleted).isGreaterThanOrEqualTo(1);
        assertThat(tickets.findById(old.getId())).isEmpty();
        assertThat(attachments.findById(file.getId())).isEmpty();
        assertThat(contents.findById(file.getId())).isEmpty();
        assertThat(tickets.findById(openOld.getId())).isPresent();
        assertThat(tickets.findById(recent.getId())).isPresent();
        assertThat(events(AuditType.RETENTION_PURGE)).last().extracting(AuditEvent::getActor).isEqualTo("system");
    }
}
