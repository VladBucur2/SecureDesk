package nl.fontys.securedesk.ticket;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AttachmentRepository extends JpaRepository<Attachment, UUID> {

    /** An attachment is resolved through its parent ticket, never on its own (SC-03). */
    Optional<Attachment> findByIdAndTicketId(UUID id, UUID ticketId);

    List<Attachment> findByTicketIdOrderByCreatedAtAsc(UUID ticketId);

    long countByTicketId(UUID ticketId);

    @Modifying
    @Query("delete from Attachment a where a.ticketId in :ticketIds")
    int deleteByTicketIds(@Param("ticketIds") List<UUID> ticketIds);
}
