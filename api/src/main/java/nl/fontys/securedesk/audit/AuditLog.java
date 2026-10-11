package nl.fontys.securedesk.audit;

import nl.fontys.securedesk.auth.CurrentUser;
import nl.fontys.securedesk.auth.SessionUser;
import nl.fontys.securedesk.common.RequestContext;
import nl.fontys.securedesk.user.AppUser;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.Clock;
import java.util.Optional;
import java.util.UUID;

/**
 * What the rest of the application calls to record a security event:
 *
 * <pre>
 * audit.event(AuditType.USER_ROLE_CHANGED).target("user", user.getId())
 *      .detail("old_role", "REQUESTER").detail("new_role", "ADMIN").write();
 * </pre>
 *
 * The actor defaults to the signed-in user of the current request. The source IP, session hash
 * and correlation id are taken from the request, never from the caller, so they cannot be
 * supplied wrongly.
 *
 * <p>A SUCCESS event written inside a transaction is held until the transaction ends. If it
 * commits, the event is written as it is; if it rolls back, the event is written with outcome
 * FAILURE and {@code rolled_back=true}. The trail therefore never claims a change that did not
 * happen, and never loses an attempt. Any other outcome (a refusal, a failed check) is a fact
 * whatever happens to the transaction, and is written at once in a transaction of its own.
 */
@Component
public class AuditLog {

    private final AuditWriter writer;
    private final Clock clock;

    public AuditLog(AuditWriter writer, Clock clock) {
        this.writer = writer;
        this.clock = clock;
    }

    public Entry event(AuditType type) {
        return new Entry(type);
    }

    public final class Entry {

        private final AuditType type;
        private Outcome outcome = Outcome.SUCCESS;
        private boolean alert;
        private String actorId;
        private String actor;
        private String actorRole;
        private String targetType = "-";
        private String targetId = "-";
        private final AuditDetails details = new AuditDetails();

        private Entry(AuditType type) {
            this.type = type;
            this.alert = type.alert();
            Optional<SessionUser> current = CurrentUser.get();
            current.ifPresent(this::actor);
        }

        public Entry outcome(Outcome value) {
            this.outcome = value;
            return this;
        }

        /** For events that are only sometimes alert-worthy, such as a burst of failures. */
        public Entry alert(boolean value) {
            this.alert = this.alert || value;
            return this;
        }

        public Entry actor(AppUser user) {
            this.actorId = user.getId().toString();
            this.actor = user.getUsername();
            this.actorRole = user.getRole().name();
            return this;
        }

        public Entry actor(SessionUser user) {
            this.actorId = user.id().toString();
            this.actor = user.username();
            this.actorRole = user.role().name();
            return this;
        }

        /** No known account: an unknown username is never written, in case it is a mistyped password. */
        public Entry anonymous() {
            this.actorId = null;
            this.actor = null;
            this.actorRole = null;
            return this;
        }

        public Entry system() {
            this.actorId = "-";
            this.actor = "system";
            this.actorRole = "SYSTEM";
            return this;
        }

        public Entry target(String type, Object id) {
            this.targetType = type;
            this.targetId = String.valueOf(id);
            return this;
        }

        public Entry detail(String key, Object value) {
            details.put(key, value);
            return this;
        }

        public void write() {
            AuditRecord record = new AuditRecord(
                    UUID.randomUUID().toString(),
                    clock.instant(),
                    type,
                    outcome,
                    alert,
                    orDash(actorId),
                    orDash(actor),
                    orDash(actorRole),
                    RequestContext.sourceIp(),
                    RequestContext.sessionHash(),
                    targetType,
                    targetId,
                    RequestContext.correlationId(),
                    details);
            if (outcome == Outcome.SUCCESS
                    && TransactionSynchronizationManager.isActualTransactionActive()
                    && TransactionSynchronizationManager.isSynchronizationActive()) {
                TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                    @Override
                    public void afterCompletion(int status) {
                        writer.append(status == STATUS_COMMITTED ? record : record.rolledBack());
                    }
                });
            } else {
                writer.append(record);
            }
        }

        private static String orDash(String value) {
            return value == null || value.isBlank() ? "-" : value;
        }
    }
}
