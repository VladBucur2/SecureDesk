package nl.fontys.securedesk.ticket;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import nl.fontys.securedesk.common.PageResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.util.UUID;

/** UC-02 and UC-03: a requester's own tickets. Nobody else's are reachable from here. */
@RestController
@RequestMapping("/api/tickets")
public class RequesterTicketController {

    private final TicketService tickets;
    private final AttachmentService attachments;

    public RequesterTicketController(TicketService tickets, AttachmentService attachments) {
        this.tickets = tickets;
        this.attachments = attachments;
    }

    @GetMapping
    @PreAuthorize("hasRole('REQUESTER')")
    public PageResponse<TicketDtos.TicketSummary> list(@RequestParam(defaultValue = "0") @Min(0) int page,
                                                       @RequestParam(defaultValue = "20") @Min(1) @Max(PageResponse.MAX_SIZE) int size) {
        return PageResponse.of(tickets.listOwn(page, size), summary -> summary);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('REQUESTER')")
    public TicketDtos.RequesterTicketView create(@Valid @RequestBody TicketDtos.CreateTicketRequest body) {
        return tickets.create(body);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('REQUESTER')")
    public TicketDtos.RequesterTicketView view(@PathVariable UUID id) {
        return tickets.viewOwn(id);
    }

    @PostMapping("/{id}/comments")
    @PreAuthorize("hasRole('REQUESTER')")
    public TicketDtos.RequesterTicketView comment(@PathVariable UUID id,
                                                  @Valid @RequestBody TicketDtos.CommentRequest body) {
        return tickets.commentOwn(id, body);
    }

    @PostMapping(value = "/{id}/attachments", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('REQUESTER')")
    public TicketDtos.AttachmentView upload(@PathVariable UUID id, @RequestPart("file") MultipartFile file) {
        return attachments.uploadToOwnTicket(id, file);
    }

    @GetMapping("/{id}/attachments/{attachmentId}")
    @PreAuthorize("hasRole('REQUESTER')")
    public ResponseEntity<byte[]> download(@PathVariable UUID id, @PathVariable UUID attachmentId) {
        return AttachmentResponses.download(attachments.downloadFromOwnTicket(id, attachmentId));
    }
}
