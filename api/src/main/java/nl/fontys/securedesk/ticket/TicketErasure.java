package nl.fontys.securedesk.ticket;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Deletes tickets with everything that hangs off them: attachment content, attachments, comments.
 * Used by the retention job (SC-11) and by the erasure of a user (SR-10). It runs as a service
 * job, not on behalf of a requester, so it is not routed through TicketAccessService; its callers
 * are the administrator-only erasure and the scheduled retention run.
 */
@Service
public class TicketErasure {

    private static final int CHUNK = 200;

    public record Result(int ticketsDeleted, int ticketsUnassigned) {
    }

    private final TicketRepository tickets;
    private final TicketCommentRepository comments;
    private final AttachmentRepository attachments;
    private final AttachmentContentRepository contents;

    public TicketErasure(TicketRepository tickets, TicketCommentRepository comments,
                         AttachmentRepository attachments, AttachmentContentRepository contents) {
        this.tickets = tickets;
        this.comments = comments;
        this.attachments = attachments;
        this.contents = contents;
    }

    /** Every ticket the user filed is deleted; tickets assigned to them become unassigned. */
    @Transactional
    public Result eraseFor(UUID userId) {
        int deleted = delete(tickets.findIdsByRequesterId(userId));
        int unassigned = tickets.unassignAll(userId);
        return new Result(deleted, unassigned);
    }

    @Transactional
    public int delete(List<UUID> ticketIds) {
        int deleted = 0;
        for (int from = 0; from < ticketIds.size(); from += CHUNK) {
            List<UUID> chunk = ticketIds.subList(from, Math.min(from + CHUNK, ticketIds.size()));
            contents.deleteByTicketIds(chunk);
            attachments.deleteByTicketIds(chunk);
            comments.deleteByTicketIds(chunk);
            deleted += tickets.deleteByIds(chunk);
        }
        return deleted;
    }
}
