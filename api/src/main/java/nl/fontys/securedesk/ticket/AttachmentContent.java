package nl.fontys.securedesk.ticket;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.springframework.data.domain.Persistable;

import java.util.UUID;

/**
 * The bytes of one attachment, in a table of their own so that listing attachments never loads
 * them. The prototype keeps them in MySQL behind {@link AttachmentService}; see
 * docs/adr/0004-attachments-in-the-database.md for why there is no object store.
 */
@Entity
@Table(name = "attachment_content")
public class AttachmentContent implements Persistable<UUID> {

    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "attachment_id", length = 36)
    private UUID attachmentId;

    @Lob
    @Column(nullable = false)
    private byte[] content;

    @jakarta.persistence.Transient
    private boolean fresh;

    protected AttachmentContent() {
    }

    public AttachmentContent(UUID attachmentId, byte[] content) {
        this.attachmentId = attachmentId;
        this.content = content;
        this.fresh = true;
    }

    public byte[] getContent() {
        return content;
    }

    @Override
    public UUID getId() {
        return attachmentId;
    }

    @Override
    public boolean isNew() {
        return fresh;
    }
}
