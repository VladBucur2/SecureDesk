package nl.fontys.securedesk.audit;

import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/** OWASP Logging Cheat Sheet: start-ups and shut-downs are among the events to always log. */
@Component
class LifecycleEvents {

    private final AuditLog audit;

    LifecycleEvents(AuditLog audit) {
        this.audit = audit;
    }

    @EventListener(ApplicationReadyEvent.class)
    void started() {
        audit.event(AuditType.APP_STARTED).system()
                .detail("java", Runtime.version().feature())
                .write();
    }

    @EventListener
    void stopping(ContextClosedEvent event) {
        // The management server has a child context of its own; only the root one is the API.
        if (event.getApplicationContext().getParent() == null) {
            audit.event(AuditType.APP_STOPPING).system().write();
        }
    }
}
