package nl.fontys.securedesk.ticket;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import nl.fontys.securedesk.common.BaseEntity;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.Locale;
import java.util.UUID;

/**
 * A ticket. Ownership is the requester id, compared with the authenticated principal in
 * {@link TicketAccessService} and nowhere else. The setters for status, priority and assignee
 * are only ever called from the agent operations; the requester's request body has no such
 * fields at all.
 */
@Entity
@Table(name = "ticket")
public class Ticket extends BaseEntity {

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "requester_id", nullable = false, length = 36, updatable = false)
    private UUID requesterId;

    @Column(name = "category_id", nullable = false)
    private Long categoryId;

    @Column(nullable = false, length = 200)
    private String title;

    @Column(nullable = false, length = 10000)
    private String description;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(nullable = false, length = 24)
    private TicketStatus status = TicketStatus.NEW;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(nullable = false, length = 16)
    private TicketPriority priority = TicketPriority.NORMAL;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "assignee_id", length = 36)
    private UUID assigneeId;

    @Column(length = 2000)
    private String resolution;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "closed_at")
    private Instant closedAt;

    @Version
    private long version;

    protected Ticket() {
    }

    public Ticket(UUID requesterId, Long categoryId, String title, String description, Instant now) {
        this.requesterId = requesterId;
        this.categoryId = categoryId;
        this.title = title;
        this.description = description;
        this.createdAt = now;
        this.updatedAt = now;
    }

    /** A short, non-sequential reference for people and mail: the start of the UUID. */
    public String reference() {
        return "SD-" + getId().toString().substring(0, 8).toUpperCase(Locale.ROOT);
    }

    void changeStatus(TicketStatus newStatus, Instant now) {
        if (newStatus == TicketStatus.CLOSED && status != TicketStatus.CLOSED) {
            closedAt = now;
        } else if (newStatus != TicketStatus.CLOSED) {
            closedAt = null;
        }
        status = newStatus;
    }

    void touch(Instant now) {
        updatedAt = now;
    }

    public UUID getRequesterId() {
        return requesterId;
    }

    public Long getCategoryId() {
        return categoryId;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    public TicketStatus getStatus() {
        return status;
    }

    public TicketPriority getPriority() {
        return priority;
    }

    void setPriority(TicketPriority priority) {
        this.priority = priority;
    }

    public UUID getAssigneeId() {
        return assigneeId;
    }

    void setAssigneeId(UUID assigneeId) {
        this.assigneeId = assigneeId;
    }

    public String getResolution() {
        return resolution;
    }

    void setResolution(String resolution) {
        this.resolution = resolution;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public Instant getClosedAt() {
        return closedAt;
    }
}
