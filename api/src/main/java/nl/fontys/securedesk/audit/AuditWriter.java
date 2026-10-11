package nl.fontys.securedesk.audit;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Appends events to the chain: one writer, one event at a time. Each event is inserted in a
 * transaction of its own, and only after the insert has committed does the head of the chain
 * move on, the event go to stdout as one JSON line, and the event go to the collector.
 *
 * <p>The single writer is what makes the chain linear; it holds because SecureDesk runs as one
 * instance (SC-10). Should a second writer ever insert a row, the primary key on {@code seq}
 * refuses the duplicate and this writer re-reads the head before retrying.
 *
 * <p>A lock rather than {@code synchronized}: requests run on virtual threads, and on Java 21 a
 * virtual thread blocked inside {@code synchronized} pins its carrier thread, which together
 * with a full connection pool can stall the whole application.
 */
@Component
public class AuditWriter {

    private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT");
    private static final Logger LOG = LoggerFactory.getLogger(AuditWriter.class);

    @PersistenceContext
    private EntityManager entityManager;

    private final TransactionTemplate newTransaction;
    private final AuditForwarder forwarder;
    private final ReentrantLock lock = new ReentrantLock();

    private boolean initialised;
    private long lastSeq;
    private String head;

    public AuditWriter(PlatformTransactionManager transactionManager, AuditForwarder forwarder) {
        this.newTransaction = new TransactionTemplate(transactionManager);
        this.newTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.forwarder = forwarder;
    }

    void append(AuditRecord record) {
        lock.lock();
        try {
            appendLocked(record);
        } finally {
            lock.unlock();
        }
    }

    private void appendLocked(AuditRecord record) {
        for (int attempt = 1; attempt <= 2; attempt++) {
            try {
                if (!initialised) {
                    readHead();
                }
                AuditEvent event = new AuditEvent(lastSeq + 1, record, head);
                newTransaction.executeWithoutResult(status -> entityManager.persist(event));
                lastSeq = event.getSeq();
                head = event.getEntryHash();
                AUDIT.info(event.toJsonLine());
                forwarder.forward(event);
                return;
            } catch (RuntimeException e) {
                initialised = false;
                if (attempt == 2) {
                    // The event is lost from the table, so at least the application log keeps the
                    // fact. Only fields that are safe by construction are printed.
                    LOG.error("audit event could not be stored: type={} outcome={} actor={} correlation_id={}",
                            record.type(), record.outcome(), record.actor(), record.correlationId(), e);
                }
            }
        }
    }

    /** The last sequence number this process wrote or read, for the tail check; -1 if none yet. */
    long lastSeq() {
        lock.lock();
        try {
            return initialised ? lastSeq : -1;
        } finally {
            lock.unlock();
        }
    }

    private void readHead() {
        List<AuditEvent> last = newTransaction.execute(status -> entityManager
                .createQuery("select e from AuditEvent e order by e.seq desc", AuditEvent.class)
                .setMaxResults(1)
                .getResultList());
        if (last == null || last.isEmpty()) {
            lastSeq = 0;
            head = AuditEvent.GENESIS;
        } else {
            lastSeq = last.get(0).getSeq();
            head = last.get(0).getEntryHash();
        }
        initialised = true;
    }
}
