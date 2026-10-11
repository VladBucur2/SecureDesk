package nl.fontys.securedesk.ticket;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import nl.fontys.securedesk.user.Role;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Request DTOs are separated per role (BoK 5.2.3 B): the status, assignee and owner fields
 * simply do not exist in what a requester can send, which closes the mass-assignment path of
 * T-07. Response DTOs are separated the same way: the requester's view of a ticket has no
 * internal notes and no field that could carry one.
 */
public final class TicketDtos {

    private TicketDtos() {
    }

    // ---- requester ------------------------------------------------------------------------------

    public record CreateTicketRequest(@NotNull Long categoryId,
                                      @NotBlank @Size(max = 200) String title,
                                      @NotBlank @Size(max = 10000) String description) {
    }

    public record CommentRequest(@NotBlank @Size(max = 5000) String body) {
    }

    public record TicketSummary(UUID id, String reference, String title, String category, TicketStatus status,
                                TicketPriority priority, Instant createdAt, Instant updatedAt) {
    }

    public record RequesterTicketView(UUID id, String reference, String title, String description, String category,
                                      TicketStatus status, TicketPriority priority, String assigneeName,
                                      String resolution, Instant createdAt, Instant updatedAt, Instant closedAt,
                                      List<PublicComment> comments, List<AttachmentView> attachments) {
    }

    /** {@code fromSupport} instead of a role: the requester needs to know who answered, not how the desk is organised. */
    public record PublicComment(UUID id, String authorName, boolean fromSupport, String body, Instant createdAt) {
    }

    // ---- agent ----------------------------------------------------------------------------------

    public record AgentUpdateRequest(@NotNull TicketStatus status,
                                     @NotNull TicketPriority priority,
                                     UUID assigneeId,
                                     @Size(max = 2000) String resolution) {
    }

    public record AgentCommentRequest(@NotBlank @Size(max = 5000) String body, @NotNull Boolean internal) {
    }

    public record QueueItem(UUID id, String reference, String title, String category, TicketStatus status,
                            TicketPriority priority, String requesterName, UUID assigneeId, String assigneeName,
                            Instant createdAt, Instant updatedAt) {
    }

    public record AgentTicketView(UUID id, String reference, String title, String description, Long categoryId,
                                  String category, TicketStatus status, TicketPriority priority, Person requester,
                                  UUID assigneeId, String assigneeName, String resolution, Instant createdAt,
                                  Instant updatedAt, Instant closedAt, List<AgentComment> comments,
                                  List<AttachmentView> attachments) {
    }

    public record AgentComment(UUID id, String authorName, Role authorRole, boolean internal, String body,
                               Instant createdAt) {
    }

    public record Person(UUID id, String username, String displayName) {
    }

    // ---- shared ---------------------------------------------------------------------------------

    public record AttachmentView(UUID id, String name, String mediaType, long size, String uploadedBy,
                                 Instant createdAt) {
    }

    public record CategoryView(Long id, String name, boolean active) {
        public static CategoryView of(Category category) {
            return new CategoryView(category.getId(), category.getName(), category.isActive());
        }
    }

    public record CategoryRequest(@NotBlank @Size(max = 60) String name, Boolean active) {
    }
}
