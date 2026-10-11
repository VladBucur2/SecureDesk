package nl.fontys.securedesk.ticket;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface AttachmentContentRepository extends JpaRepository<AttachmentContent, UUID> {

    @Modifying
    @Query("delete from AttachmentContent c where c.attachmentId in "
            + "(select a.id from Attachment a where a.ticketId in :ticketIds)")
    int deleteByTicketIds(@Param("ticketIds") List<UUID> ticketIds);
}
