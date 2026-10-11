package nl.fontys.securedesk.ticket;

import nl.fontys.securedesk.audit.AuditLog;
import nl.fontys.securedesk.audit.AuditType;
import nl.fontys.securedesk.auth.CurrentUser;
import nl.fontys.securedesk.auth.SessionUser;
import nl.fontys.securedesk.common.ApiException;
import nl.fontys.securedesk.common.TextSanitizer;
import nl.fontys.securedesk.notify.TicketNotifier;
import nl.fontys.securedesk.user.AppUser;
import nl.fontys.securedesk.user.AppUserRepository;
import nl.fontys.securedesk.user.Role;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * UC-02 to UC-04. Every operation starts with {@link TicketAccessService}; nothing here looks a
 * ticket up by id on its own.
 */
@Service
public class TicketService {

    private final TicketAccessService access;
    private final TicketRepository tickets;
    private final TicketCommentRepository comments;
    private final AttachmentRepository attachments;
    private final CategoryRepository categories;
    private final AppUserRepository users;
    private final TicketNotifier notifier;
    private final AuditLog audit;
    private final Clock clock;

    public TicketService(TicketAccessService access, TicketRepository tickets, TicketCommentRepository comments,
                         AttachmentRepository attachments, CategoryRepository categories, AppUserRepository users,
                         TicketNotifier notifier, AuditLog audit, Clock clock) {
        this.access = access;
        this.tickets = tickets;
        this.comments = comments;
        this.attachments = attachments;
        this.categories = categories;
        this.users = users;
        this.notifier = notifier;
        this.audit = audit;
        this.clock = clock;
    }

    // ---- requester ------------------------------------------------------------------------------

    /** UC-02. The owner is the principal; status and priority start at their defaults. */
    @Transactional
    public TicketDtos.RequesterTicketView create(TicketDtos.CreateTicketRequest request) {
        SessionUser me = CurrentUser.require();
        Category category = categories.findById(request.categoryId())
                .filter(Category::isActive)
                .orElseThrow(() -> ApiException.badRequest("unknown_category", "Choose one of the listed categories."));
        String title = requireText(TextSanitizer.cleanLine(request.title()), "title");
        String description = requireText(TextSanitizer.clean(request.description()), "description");
        Ticket ticket = tickets.save(new Ticket(me.id(), category.getId(), title, description, clock.instant()));
        audit.event(AuditType.TICKET_CREATED).target("ticket", ticket.getId())
                .detail("category", category.getId()).write();
        return requesterView(ticket);
    }

    public Page<TicketDtos.TicketSummary> listOwn(int page, int size) {
        SessionUser me = CurrentUser.require();
        Page<Ticket> result = tickets.findByRequesterIdOrderByUpdatedAtDesc(me.id(), PageRequest.of(page, size));
        Map<Long, String> categoryNames = categoryNames();
        return result.map(t -> new TicketDtos.TicketSummary(t.getId(), t.reference(), t.getTitle(),
                categoryNames.get(t.getCategoryId()), t.getStatus(), t.getPriority(), t.getCreatedAt(), t.getUpdatedAt()));
    }

    public TicketDtos.RequesterTicketView viewOwn(UUID ticketId) {
        return requesterView(access.ownTicket(ticketId));
    }

    /** UC-03. A requester's comment is always public; replying to a waiting ticket puts it back in progress. */
    @Transactional
    public TicketDtos.RequesterTicketView commentOwn(UUID ticketId, TicketDtos.CommentRequest request) {
        Ticket ticket = access.ownTicket(ticketId);
        requireOpen(ticket);
        Instant now = clock.instant();
        String body = requireText(TextSanitizer.clean(request.body()), "body");
        comments.save(new TicketComment(ticket.getId(), CurrentUser.require().id(), body, false, now));
        if (ticket.getStatus() == TicketStatus.WAITING_ON_REQUESTER || ticket.getStatus() == TicketStatus.RESOLVED) {
            ticket.changeStatus(TicketStatus.IN_PROGRESS, now);
        }
        ticket.touch(now);
        tickets.save(ticket);
        audit.event(AuditType.COMMENT_ADDED).target("ticket", ticket.getId()).detail("internal", false).write();
        return requesterView(ticket);
    }

    // ---- agent ----------------------------------------------------------------------------------

    public Page<TicketDtos.QueueItem> queue(TicketStatus status, Long categoryId, String assignee, String search,
                                           int page, int size) {
        UUID assigneeId = null;
        boolean unassigned = false;
        if ("me".equals(assignee)) {
            assigneeId = CurrentUser.require().id();
        } else if ("none".equals(assignee)) {
            unassigned = true;
        }
        String pattern = search == null || search.isBlank() ? null
                : "%" + escapeLike(search.strip().toLowerCase(Locale.ROOT)) + "%";
        Page<Ticket> result = tickets.searchQueue(status, categoryId, assigneeId, unassigned, pattern,
                PageRequest.of(page, size));
        Map<Long, String> categoryNames = categoryNames();
        Set<UUID> people = new HashSet<>();
        result.forEach(t -> {
            people.add(t.getRequesterId());
            if (t.getAssigneeId() != null) {
                people.add(t.getAssigneeId());
            }
        });
        Map<UUID, AppUser> byId = usersById(people);
        return result.map(t -> new TicketDtos.QueueItem(t.getId(), t.reference(), t.getTitle(),
                categoryNames.get(t.getCategoryId()), t.getStatus(), t.getPriority(),
                name(byId, t.getRequesterId()), t.getAssigneeId(), name(byId, t.getAssigneeId()),
                t.getCreatedAt(), t.getUpdatedAt()));
    }

    public TicketDtos.AgentTicketView viewForAgent(UUID ticketId) {
        return agentView(access.queueTicket(ticketId));
    }

    /** UC-04: assign, prioritise, change status, close with a resolution. Every change is audited. */
    @Transactional
    public TicketDtos.AgentTicketView update(UUID ticketId, TicketDtos.AgentUpdateRequest request) {
        Ticket ticket = access.queueTicket(ticketId);
        if (request.assigneeId() != null) {
            AppUser assignee = users.findById(request.assigneeId())
                    .filter(u -> u.getRole() == Role.AGENT && u.isEnabled() && !u.isErased())
                    .orElseThrow(() -> ApiException.badRequest("unknown_agent", "Tickets can only be assigned to an agent."));
            request = new TicketDtos.AgentUpdateRequest(request.status(), request.priority(), assignee.getId(),
                    request.resolution());
        }
        String resolution = TextSanitizer.clean(request.resolution());
        if (resolution != null && resolution.isEmpty()) {
            resolution = null;
        }
        List<String> changed = new ArrayList<>();
        Instant now = clock.instant();
        if (ticket.getStatus() != request.status()) {
            changed.add("status");
            ticket.changeStatus(request.status(), now);
        }
        if (ticket.getPriority() != request.priority()) {
            changed.add("priority");
            ticket.setPriority(request.priority());
        }
        if (!Objects.equals(ticket.getAssigneeId(), request.assigneeId())) {
            changed.add("assignee");
            ticket.setAssigneeId(request.assigneeId());
        }
        if (!Objects.equals(ticket.getResolution(), resolution)) {
            changed.add("resolution");
            ticket.setResolution(resolution);
        }
        if (changed.isEmpty()) {
            return agentView(ticket);
        }
        ticket.touch(now);
        tickets.save(ticket);
        audit.event(AuditType.TICKET_UPDATED).target("ticket", ticket.getId())
                .detail("fields", String.join(",", changed))
                .detail("status", ticket.getStatus())
                .detail("priority", ticket.getPriority())
                .detail("assignee_id", ticket.getAssigneeId() == null ? "-" : ticket.getAssigneeId()).write();
        if (changed.contains("status") || changed.contains("assignee")) {
            notifier.ticketChanged(ticket.getId(), ticket.getRequesterId(), ticket.reference());
        }
        return agentView(ticket);
    }

    /** US-05: internal notes for the agents, or a public comment the requester is told about. */
    @Transactional
    public TicketDtos.AgentTicketView commentAsAgent(UUID ticketId, TicketDtos.AgentCommentRequest request) {
        Ticket ticket = access.queueTicket(ticketId);
        Instant now = clock.instant();
        String body = requireText(TextSanitizer.clean(request.body()), "body");
        boolean internal = request.internal();
        comments.save(new TicketComment(ticket.getId(), CurrentUser.require().id(), body, internal, now));
        ticket.touch(now);
        tickets.save(ticket);
        audit.event(AuditType.COMMENT_ADDED).target("ticket", ticket.getId()).detail("internal", internal).write();
        if (!internal) {
            notifier.ticketChanged(ticket.getId(), ticket.getRequesterId(), ticket.reference());
        }
        return agentView(ticket);
    }

    public List<TicketDtos.Person> agents() {
        return users.findByRoleAndEnabledTrueAndErasedAtIsNullOrderByDisplayNameAsc(Role.AGENT).stream()
                .map(u -> new TicketDtos.Person(u.getId(), u.getUsername(), u.getDisplayName())).toList();
    }

    // ---- views ----------------------------------------------------------------------------------

    TicketDtos.RequesterTicketView requesterView(Ticket ticket) {
        List<TicketComment> visible = comments.findByTicketIdAndInternalFalseOrderByCreatedAtAsc(ticket.getId());
        List<Attachment> files = attachments.findByTicketIdOrderByCreatedAtAsc(ticket.getId());
        Map<UUID, AppUser> byId = usersById(peopleOf(ticket, visible, files));
        List<TicketDtos.PublicComment> commentViews = visible.stream()
                .map(c -> new TicketDtos.PublicComment(c.getId(), name(byId, c.getAuthorId()),
                        !c.getAuthorId().equals(ticket.getRequesterId()), c.getBody(), c.getCreatedAt()))
                .toList();
        return new TicketDtos.RequesterTicketView(ticket.getId(), ticket.reference(), ticket.getTitle(),
                ticket.getDescription(), categoryNames().get(ticket.getCategoryId()), ticket.getStatus(),
                ticket.getPriority(), name(byId, ticket.getAssigneeId()), ticket.getResolution(),
                ticket.getCreatedAt(), ticket.getUpdatedAt(), ticket.getClosedAt(), commentViews,
                attachmentViews(files, byId));
    }

    TicketDtos.AgentTicketView agentView(Ticket ticket) {
        List<TicketComment> all = comments.findByTicketIdOrderByCreatedAtAsc(ticket.getId());
        List<Attachment> files = attachments.findByTicketIdOrderByCreatedAtAsc(ticket.getId());
        Map<UUID, AppUser> byId = usersById(peopleOf(ticket, all, files));
        AppUser requester = byId.get(ticket.getRequesterId());
        List<TicketDtos.AgentComment> commentViews = all.stream()
                .map(c -> {
                    AppUser author = byId.get(c.getAuthorId());
                    return new TicketDtos.AgentComment(c.getId(), name(byId, c.getAuthorId()),
                            author == null ? null : author.getRole(), c.isInternal(), c.getBody(), c.getCreatedAt());
                })
                .toList();
        return new TicketDtos.AgentTicketView(ticket.getId(), ticket.reference(), ticket.getTitle(),
                ticket.getDescription(), ticket.getCategoryId(), categoryNames().get(ticket.getCategoryId()),
                ticket.getStatus(), ticket.getPriority(),
                requester == null ? null : new TicketDtos.Person(requester.getId(), requester.getUsername(),
                        requester.getDisplayName()),
                ticket.getAssigneeId(), name(byId, ticket.getAssigneeId()), ticket.getResolution(),
                ticket.getCreatedAt(), ticket.getUpdatedAt(), ticket.getClosedAt(), commentViews,
                attachmentViews(files, byId));
    }

    private List<TicketDtos.AttachmentView> attachmentViews(List<Attachment> files, Map<UUID, AppUser> byId) {
        return files.stream().map(a -> new TicketDtos.AttachmentView(a.getId(), a.getDisplayName(), a.getMediaType(),
                a.getSizeBytes(), name(byId, a.getUploaderId()), a.getCreatedAt())).toList();
    }

    private static Set<UUID> peopleOf(Ticket ticket, List<TicketComment> notes, List<Attachment> files) {
        Set<UUID> ids = new HashSet<>();
        ids.add(ticket.getRequesterId());
        if (ticket.getAssigneeId() != null) {
            ids.add(ticket.getAssigneeId());
        }
        notes.forEach(c -> ids.add(c.getAuthorId()));
        files.forEach(a -> ids.add(a.getUploaderId()));
        return ids;
    }

    private Map<UUID, AppUser> usersById(Collection<UUID> ids) {
        return users.findAllById(ids).stream().collect(Collectors.toMap(AppUser::getId, Function.identity()));
    }

    private static String name(Map<UUID, AppUser> byId, UUID id) {
        if (id == null) {
            return null;
        }
        AppUser user = byId.get(id);
        return user == null ? "Unknown" : user.getDisplayName();
    }

    private Map<Long, String> categoryNames() {
        return categories.findAll().stream().collect(Collectors.toMap(Category::getId, Category::getName));
    }

    static void requireOpen(Ticket ticket) {
        if (ticket.getStatus() == TicketStatus.CLOSED) {
            throw ApiException.conflict("ticket_closed", "This ticket is closed.");
        }
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isEmpty()) {
            throw ApiException.badRequest("validation_failed", "The " + field + " is empty.");
        }
        return value;
    }

    /** The search text is data for LIKE, not a pattern: %, _ and the escape character are escaped. */
    static String escapeLike(String text) {
        return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    }
}
