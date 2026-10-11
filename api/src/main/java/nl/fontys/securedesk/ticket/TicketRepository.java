package nl.fontys.securedesk.ticket;

import org.springframework.data.domain.Limit;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Scoped finders (SC-03): a requester's ticket is looked up by id <em>and</em> owner, so a ticket
 * that is not theirs is simply not found. Only {@link TicketAccessService} and the services of
 * this package use this repository; an ArchUnit rule keeps controllers away from it.
 */
public interface TicketRepository extends JpaRepository<Ticket, UUID> {

    Optional<Ticket> findByIdAndRequesterId(UUID id, UUID requesterId);

    Page<Ticket> findByRequesterIdOrderByUpdatedAtDesc(UUID requesterId, Pageable pageable);

    /** The agent queue. Every filter is a typed, bound parameter; the search text is escaped for LIKE. */
    @Query("""
            select t from Ticket t
            where (:status is null or t.status = :status)
              and (:categoryId is null or t.categoryId = :categoryId)
              and (:assigneeId is null or t.assigneeId = :assigneeId)
              and (:unassigned = false or t.assigneeId is null)
              and (:search is null or lower(t.title) like :search escape '\\')
            order by t.updatedAt desc""")
    Page<Ticket> searchQueue(@Param("status") TicketStatus status,
                             @Param("categoryId") Long categoryId,
                             @Param("assigneeId") UUID assigneeId,
                             @Param("unassigned") boolean unassigned,
                             @Param("search") String search,
                             Pageable pageable);

    @Query("select t.id from Ticket t where t.requesterId = :requesterId")
    List<UUID> findIdsByRequesterId(@Param("requesterId") UUID requesterId);

    @Query("select t.id from Ticket t where t.status = :status and t.closedAt < :before order by t.closedAt")
    List<UUID> findIdsClosedBefore(@Param("status") TicketStatus status, @Param("before") Instant before, Limit limit);

    @Modifying
    @Query("update Ticket t set t.assigneeId = null where t.assigneeId = :userId")
    int unassignAll(@Param("userId") UUID userId);

    @Modifying
    @Query("delete from Ticket t where t.id in :ids")
    int deleteByIds(@Param("ids") List<UUID> ids);
}
