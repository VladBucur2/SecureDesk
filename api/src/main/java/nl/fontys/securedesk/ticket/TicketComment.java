package nl.fontys.securedesk.ticket;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import nl.fontys.securedesk.common.BaseEntity;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

/** A public comment, or an internal note that requesters never receive (UC-04, US-05). */
@Entity
@Table(name = "ticket_comment")
public class TicketComment extends BaseEntity {

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "ticket_id", nullable = false, length = 36, updatable = false)
    private UUID ticketId;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "author_id", nullable = false, length = 36, updatable = false)
    private UUID authorId;

    @Column(nullable = false, length = 5000, updatable = false)
    private String body;

    @Column(nullable = false, updatable = false)
    private boolean internal;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected TicketComment() {
    }

    public TicketComment(UUID ticketId, UUID authorId, String body, boolean internal, Instant now) {
        this.ticketId = ticketId;
        this.authorId = authorId;
        this.body = body;
        this.internal = internal;
        this.createdAt = now;
    }

    public UUID getTicketId() {
        return ticketId;
    }

    public UUID getAuthorId() {
        return authorId;
    }

    public String getBody() {
        return body;
    }

    public boolean isInternal() {
        return internal;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
