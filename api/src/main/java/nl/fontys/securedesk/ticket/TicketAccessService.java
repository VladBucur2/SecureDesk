package nl.fontys.securedesk.ticket;

import nl.fontys.securedesk.audit.AuditLog;
import nl.fontys.securedesk.audit.AuditType;
import nl.fontys.securedesk.audit.Outcome;
import nl.fontys.securedesk.auth.CurrentUser;
import nl.fontys.securedesk.auth.SessionUser;
import nl.fontys.securedesk.common.ApiException;
import nl.fontys.securedesk.user.Role;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

/**
 * Object-level authorisation (SC-03, BoK 5.2.3 B): the single place that decides whether the
 * principal may touch a ticket. Comments and attachments are resolved through their parent
 * ticket, so ownership is decided here and nowhere else. It is the path shared by the REST API,
 * the notification and the retention job.
 *
 * <ul>
 *   <li>The principal comes from the security context, never from a parameter, header or body.</li>
 *   <li>A requester's ticket is fetched by id <em>and</em> owner.</li>
 *   <li>A miss is 404, whether the ticket does not exist or belongs to someone else, so the status
 *       code tells a requester nothing; the audit trail does record which of the two it was.</li>
 * </ul>
 */
@Service
public class TicketAccessService {

    private final TicketRepository tickets;
    private final AttachmentRepository attachments;
    private final AuditLog audit;

    public TicketAccessService(TicketRepository tickets, AttachmentRepository attachments, AuditLog audit) {
        this.tickets = tickets;
        this.attachments = attachments;
        this.audit = audit;
    }

    /** A ticket the signed-in requester filed. */
    public Ticket ownTicket(UUID ticketId) {
        SessionUser me = CurrentUser.require();
        Optional<Ticket> ticket = me.role() == Role.REQUESTER
                ? tickets.findByIdAndRequesterId(ticketId, me.id())
                : Optional.empty();
        return ticket.orElseThrow(() -> denied("ticket", ticketId));
    }

    /** Any ticket in the queue, for an agent. Administrators are not agents and get none. */
    public Ticket queueTicket(UUID ticketId) {
        SessionUser me = CurrentUser.require();
        Optional<Ticket> ticket = me.role() == Role.AGENT ? tickets.findById(ticketId) : Optional.empty();
        return ticket.orElseThrow(() -> denied("ticket", ticketId));
    }

    /** An attachment of a ticket the caller already passed one of the checks above for. */
    public Attachment attachmentOf(Ticket ticket, UUID attachmentId) {
        return attachments.findByIdAndTicketId(attachmentId, ticket.getId())
                .orElseThrow(() -> denied("attachment", attachmentId));
    }

    private ApiException denied(String type, UUID id) {
        boolean exists = "ticket".equals(type) ? tickets.existsById(id) : attachments.existsById(id);
        audit.event(AuditType.OBJECT_ACCESS_DENIED).outcome(Outcome.DENIED).target(type, id)
                .detail("reason", exists ? "not_permitted" : "not_found").write();
        return ApiException.notFound();
    }
}
