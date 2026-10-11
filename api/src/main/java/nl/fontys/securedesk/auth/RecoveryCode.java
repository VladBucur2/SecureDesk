package nl.fontys.securedesk.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import nl.fontys.securedesk.common.BaseEntity;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

/**
 * One single-use recovery code, stored as a sealed Argon2id record exactly like a password. The
 * record is sealed with this row's id, which is why the id is assigned before the hash is made.
 */
@Entity
@Table(name = "recovery_code")
public class RecoveryCode extends BaseEntity {

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "user_id", nullable = false, length = 36)
    private UUID userId;

    @Column(name = "code_record", nullable = false, length = 512)
    private String codeRecord;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "used_at")
    private Instant usedAt;

    protected RecoveryCode() {
    }

    public RecoveryCode(UUID userId, Instant now) {
        this.userId = userId;
        this.createdAt = now;
    }

    public UUID getUserId() {
        return userId;
    }

    public String getCodeRecord() {
        return codeRecord;
    }

    public void setCodeRecord(String codeRecord) {
        this.codeRecord = codeRecord;
    }

    public Instant getUsedAt() {
        return usedAt;
    }

    public void markUsed(Instant now) {
        this.usedAt = now;
    }
}
