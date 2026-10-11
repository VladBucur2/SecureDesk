package nl.fontys.securedesk.ticket;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import nl.fontys.securedesk.common.PageResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.UUID;

/** UC-04: the agents' queue. Internal notes exist only on this side. */
@RestController
@RequestMapping("/api/queue")
public class AgentQueueController {

    private final TicketService tickets;
    private final AttachmentService attachments;

    public AgentQueueController(TicketService tickets, AttachmentService attachments) {
        this.tickets = tickets;
        this.attachments = attachments;
    }

    @GetMapping
    @PreAuthorize("hasRole('AGENT')")
    public PageResponse<TicketDtos.QueueItem> queue(
            @RequestParam(required = false) TicketStatus status,
            @RequestParam(required = false) Long categoryId,
            @RequestParam(defaultValue = "any") @Pattern(regexp = "any|me|none") String assignee,
            @RequestParam(required = false) @Size(max = 100) String q,
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(PageResponse.MAX_SIZE) int size) {
        return PageResponse.of(tickets.queue(status, categoryId, assignee, q, page, size), item -> item);
    }

    @GetMapping("/agents")
    @PreAuthorize("hasRole('AGENT')")
    public List<TicketDtos.Person> agents() {
        return tickets.agents();
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('AGENT')")
    public TicketDtos.AgentTicketView view(@PathVariable UUID id) {
        return tickets.viewForAgent(id);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('AGENT')")
    public TicketDtos.AgentTicketView update(@PathVariable UUID id, @Valid @RequestBody TicketDtos.AgentUpdateRequest body) {
        return tickets.update(id, body);
    }

    @PostMapping("/{id}/comments")
    @PreAuthorize("hasRole('AGENT')")
    public TicketDtos.AgentTicketView comment(@PathVariable UUID id,
                                              @Valid @RequestBody TicketDtos.AgentCommentRequest body) {
        return tickets.commentAsAgent(id, body);
    }

    @PostMapping(value = "/{id}/attachments", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('AGENT')")
    public TicketDtos.AttachmentView upload(@PathVariable UUID id, @RequestPart("file") MultipartFile file) {
        return attachments.uploadToQueueTicket(id, file);
    }

    @GetMapping("/{id}/attachments/{attachmentId}")
    @PreAuthorize("hasRole('AGENT')")
    public ResponseEntity<byte[]> download(@PathVariable UUID id, @PathVariable UUID attachmentId) {
        return AttachmentResponses.download(attachments.downloadFromQueueTicket(id, attachmentId));
    }
}
