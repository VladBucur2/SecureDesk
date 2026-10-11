package nl.fontys.securedesk.audit;

import nl.fontys.securedesk.support.IntegrationTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The hash chain of SC-09: altering, removing or cutting off rows is detected. Each test puts
 * the table back as it found it, since the database is shared by all integration tests.
 */
class AuditTrailTest extends IntegrationTest {

    @Autowired
    AuditChainVerifier verifier;
    @Autowired
    AuditLog audit;
    @Autowired
    JdbcTemplate jdbc;

    private long writeSome() {
        for (int i = 0; i < 3; i++) {
            audit.event(AuditType.CATEGORY_CREATED).system().detail("name", "n" + i).write();
        }
        return jdbc.queryForObject("select max(seq) from audit_event", Long.class);
    }

    @Test
    @DisplayName("the chain verifies intact, and the verification is itself an event")
    void intact() {
        writeSome();
        AuditChainVerifier.Result result = verifier.verifyAndRecord(true);
        assertThat(result.intact()).isTrue();
        assertThat(events(AuditType.AUDIT_CHAIN_VERIFIED)).isNotEmpty();
    }

    @Test
    @DisplayName("an altered row is found: its content no longer matches its hash")
    void detectsAlteration() {
        long last = writeSome();
        long target = last - 1;
        String original = jdbc.queryForObject("select outcome from audit_event where seq = ?", String.class, target);
        try {
            jdbc.update("update audit_event set outcome = 'DENIED' where seq = ?", target);
            AuditChainVerifier.Result result = verifier.verify();
            assertThat(result.intact()).isFalse();
            assertThat(result.brokenAt()).isEqualTo(target);
            assertThat(result.reason()).isEqualTo("content does not match its hash");
        } finally {
            jdbc.update("update audit_event set outcome = ? where seq = ?", original, target);
        }
        assertThat(verifier.verify().intact()).isTrue();
    }

    @Test
    @DisplayName("a removed row is found, and so is a row cut off the end")
    void detectsRemoval() {
        long last = writeSome();
        Map<String, Object> middle = jdbc.queryForMap("select * from audit_event where seq = ?", last - 1);
        Map<String, Object> tail = jdbc.queryForMap("select * from audit_event where seq = ?", last);
        try {
            jdbc.update("delete from audit_event where seq = ?", last - 1);
            assertThat(verifier.verify().reason()).isEqualTo("missing sequence number");
            reinsert(middle);

            jdbc.update("delete from audit_event where seq = ?", last);
            AuditChainVerifier.Result cut = verifier.verify();
            assertThat(cut.intact()).isFalse();
            assertThat(cut.reason()).isEqualTo("rows removed from the end of the trail");
            reinsert(tail);
        } finally {
            if (jdbc.queryForObject("select count(*) from audit_event where seq = ?", Integer.class, last - 1) == 0) {
                reinsert(middle);
            }
            if (jdbc.queryForObject("select count(*) from audit_event where seq = ?", Integer.class, last) == 0) {
                reinsert(tail);
            }
        }
        assertThat(verifier.verify().intact()).isTrue();
    }

    @Test
    @DisplayName("an event in a transaction that rolls back is kept as a failure, never as a success")
    void rolledBackChangeIsNotClaimed(@Autowired org.springframework.transaction.support.TransactionTemplate tx) {
        tx.executeWithoutResult(status -> {
            audit.event(AuditType.RETENTION_CHANGED).system().detail("new_months", 1).write();
            status.setRollbackOnly();
        });
        AuditEvent written = events(AuditType.RETENTION_CHANGED).getLast();
        assertThat(written.getOutcome()).isEqualTo("FAILURE");
        assertThat(written.getDetails()).contains("\"rolled_back\":\"true\"");
    }

    private void reinsert(Map<String, Object> row) {
        String columns = String.join(",", row.keySet());
        String marks = String.join(",", row.keySet().stream().map(k -> "?").toList());
        jdbc.update("insert into audit_event (" + columns + ") values (" + marks + ")", row.values().toArray());
    }
}
