package nl.fontys.securedesk.ticket;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface TicketCommentRepository extends JpaRepository<TicketComment, UUID> {

    /** The requester's projection: internal notes are not filtered afterwards, they are never loaded. */
    List<TicketComment> findByTicketIdAndInternalFalseOrderByCreatedAtAsc(UUID ticketId);

    List<TicketComment> findByTicketIdOrderByCreatedAtAsc(UUID ticketId);

    @Modifying
    @Query("delete from TicketComment c where c.ticketId in :ticketIds")
    int deleteByTicketIds(@Param("ticketIds") List<UUID> ticketIds);
}
