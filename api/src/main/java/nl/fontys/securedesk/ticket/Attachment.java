package nl.fontys.securedesk.ticket;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import nl.fontys.securedesk.common.BaseEntity;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

/**
 * An attachment's metadata. The content is stored under this row's random id, never under the
 * uploaded name, and is only ever served through the API (SC-05).
 */
@Entity
@Table(name = "attachment")
public class Attachment extends BaseEntity {

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "ticket_id", nullable = false, length = 36, updatable = false)
    private UUID ticketId;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "uploader_id", nullable = false, length = 36, updatable = false)
    private UUID uploaderId;

    @Column(name = "display_name", nullable = false, length = 120, updatable = false)
    private String displayName;

    @Column(name = "media_type", nullable = false, length = 64, updatable = false)
    private String mediaType;

    @Column(name = "size_bytes", nullable = false, updatable = false)
    private long sizeBytes;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(nullable = false, length = 64, updatable = false)
    private String sha256;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected Attachment() {
    }

    public Attachment(UUID ticketId, UUID uploaderId, String displayName, String mediaType, long sizeBytes,
                      String sha256, Instant now) {
        this.ticketId = ticketId;
        this.uploaderId = uploaderId;
        this.displayName = displayName;
        this.mediaType = mediaType;
        this.sizeBytes = sizeBytes;
        this.sha256 = sha256;
        this.createdAt = now;
    }

    public UUID getTicketId() {
        return ticketId;
    }

    public UUID getUploaderId() {
        return uploaderId;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getMediaType() {
        return mediaType;
    }

    public long getSizeBytes() {
        return sizeBytes;
    }

    public String getSha256() {
        return sha256;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
