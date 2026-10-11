package nl.fontys.securedesk.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import jakarta.persistence.Transient;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One row of the audit trail. Immutable once built: there are no setters, the repository offers
 * no save or delete, and the database account has no UPDATE or DELETE on the table.
 *
 * <p>The fields are those of BoK 5.2.3 C: event id, UTC timestamp, event type, actor id and role,
 * source IP, a hash of the session id, target object type and id, outcome and correlation id,
 * plus the category and alert flag that detection rules select on.
 */
@Entity
@Table(name = "audit_event")
public class AuditEvent {

    public static final String GENESIS = "0".repeat(64);
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'")
            .withZone(java.time.ZoneOffset.UTC);

    @Id
    private long seq;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "event_id", nullable = false, length = 36)
    private String eventId;

    @Column(nullable = false)
    private Instant ts;

    @Column(name = "event_type", nullable = false, length = 40)
    private String eventType;

    @Column(nullable = false, length = 16)
    private String category;

    @Column(nullable = false, length = 16)
    private String outcome;

    @Column(nullable = false)
    private boolean alert;

    @Column(name = "actor_id", nullable = false, length = 36)
    private String actorId;

    @Column(nullable = false, length = 64)
    private String actor;

    @Column(name = "actor_role", nullable = false, length = 16)
    private String actorRole;

    @Column(name = "src_ip", nullable = false, length = 45)
    private String srcIp;

    @Column(name = "session_hash", nullable = false, length = 16)
    private String sessionHash;

    @Column(name = "target_type", nullable = false, length = 24)
    private String targetType;

    @Column(name = "target_id", nullable = false, length = 64)
    private String targetId;

    @Column(name = "correlation_id", nullable = false, length = 64)
    private String correlationId;

    @Column(nullable = false, length = 2000)
    private String details;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "prev_hash", nullable = false, length = 64)
    private String prevHash;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "entry_hash", nullable = false, length = 64)
    private String entryHash;

    /** The details as a map, for the JSON line; only present on events written by this process. */
    @Transient
    private Map<String, String> detailMap;

    protected AuditEvent() {
    }

    AuditEvent(long seq, AuditRecord record, String prevHash) {
        this.seq = seq;
        this.eventId = record.eventId();
        // Microseconds: what DATETIME(6) stores, so the row reads back exactly as it was hashed.
        this.ts = record.ts().truncatedTo(ChronoUnit.MICROS);
        this.eventType = record.type().name();
        this.category = record.type().category().name();
        this.outcome = record.outcome().name();
        this.alert = record.alert();
        this.actorId = record.actorId();
        this.actor = record.actor();
        this.actorRole = record.actorRole();
        this.srcIp = record.srcIp();
        this.sessionHash = record.sessionHash();
        this.targetType = record.targetType();
        this.targetId = record.targetId();
        this.correlationId = record.correlationId();
        this.details = record.details().toJson();
        this.detailMap = record.details().asMap();
        this.prevHash = prevHash;
        this.entryHash = computeHash();
    }

    /** Everything except the entry hash itself, in a fixed order. */
    Map<String, Object> canonicalFields() {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("seq", String.valueOf(seq));
        fields.put("event_id", eventId);
        fields.put("ts", TS.format(ts));
        fields.put("event", eventType);
        fields.put("category", category);
        fields.put("outcome", outcome);
        fields.put("alert", alert);
        fields.put("actor_id", actorId);
        fields.put("actor", actor);
        fields.put("actor_role", actorRole);
        fields.put("src_ip", srcIp);
        fields.put("session", sessionHash);
        fields.put("target_type", targetType);
        fields.put("target_id", targetId);
        fields.put("correlation_id", correlationId);
        fields.put("details", details);
        fields.put("prev_hash", prevHash);
        return fields;
    }

    String canonicalForm() {
        return CanonicalJson.write(canonicalFields());
    }

    /** SHA-256 over the canonical form, which includes the previous row's hash. */
    String computeHash() {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(canonicalForm().getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * The JSON line for stdout and the collector: the canonical fields plus the entry hash, with
     * the details as a nested object for the SIEM. Writing that object with {@link CanonicalJson}
     * gives back exactly the stored string, so the hash can be checked from the collector's copy.
     */
    String toJsonLine() {
        Map<String, Object> fields = canonicalFields();
        if (detailMap != null) {
            fields.put("details", detailMap);
        }
        fields.put("stream", "audit");
        fields.put("hash", entryHash);
        return CanonicalJson.write(fields);
    }

    public long getSeq() {
        return seq;
    }

    public String getEventId() {
        return eventId;
    }

    public Instant getTs() {
        return ts;
    }

    public String getEventType() {
        return eventType;
    }

    public String getCategory() {
        return category;
    }

    public String getOutcome() {
        return outcome;
    }

    public boolean isAlert() {
        return alert;
    }

    public String getActorId() {
        return actorId;
    }

    public String getActor() {
        return actor;
    }

    public String getActorRole() {
        return actorRole;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public String getSessionHash() {
        return sessionHash;
    }

    public String getTargetType() {
        return targetType;
    }

    public String getTargetId() {
        return targetId;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public String getDetails() {
        return details;
    }

    public String getPrevHash() {
        return prevHash;
    }

    public String getEntryHash() {
        return entryHash;
    }
}
