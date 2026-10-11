package nl.fontys.securedesk.audit;

import org.springframework.data.domain.Limit;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Read-only by construction: this extends {@link Repository}, not {@code JpaRepository}, so there
 * is no save, no delete and no update to call. Rows are inserted by {@link AuditWriter} only.
 */
public interface AuditEventRepository extends Repository<AuditEvent, Long> {

    /** Every filter is a typed, bound parameter (SC-04). */
    @Query("""
            select e from AuditEvent e
            where (:type is null or e.eventType = :type)
              and (:category is null or e.category = :category)
              and (:actor is null or e.actor = :actor)
              and (:fromTs is null or e.ts >= :fromTs)
              and (:toTs is null or e.ts < :toTs)
              and (:alertOnly = false or e.alert = true)
            order by e.seq desc""")
    Page<AuditEvent> search(@Param("type") String type,
                            @Param("category") String category,
                            @Param("actor") String actor,
                            @Param("fromTs") Instant fromTs,
                            @Param("toTs") Instant toTs,
                            @Param("alertOnly") boolean alertOnly,
                            Pageable pageable);

    List<AuditEvent> findBySeqGreaterThanOrderBySeqAsc(long seq, Limit limit);

    Optional<AuditEvent> findTopByOrderBySeqDesc();

    List<AuditEvent> findByEventTypeOrderBySeqAsc(String eventType);

    long count();
}
