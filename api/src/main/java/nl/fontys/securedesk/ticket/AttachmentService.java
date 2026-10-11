package nl.fontys.securedesk.ticket;

import nl.fontys.securedesk.audit.AuditLog;
import nl.fontys.securedesk.audit.AuditType;
import nl.fontys.securedesk.audit.Outcome;
import nl.fontys.securedesk.auth.CurrentUser;
import nl.fontys.securedesk.common.ApiException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.unit.DataSize;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.time.Clock;
import java.util.HexFormat;
import java.util.Locale;
import java.util.UUID;

/**
 * File upload handling (SC-05, MU-05): a size limit, a type allow-list verified against the
 * content, an extension that must agree with the content, a refusal of active PDF content, the
 * malware-scan interface, a server-side random key, storage outside any web root, and retrieval
 * only through the API with Content-Disposition: attachment.
 */
@Service
public class AttachmentService {

    public record Download(Attachment attachment, byte[] content) {
    }

    private final TicketAccessService access;
    private final AttachmentRepository attachments;
    private final AttachmentContentRepository contents;
    private final TicketRepository tickets;
    private final MalwareScanner scanner;
    private final AuditLog audit;
    private final Clock clock;
    private final long maxBytes;
    private final int maxPerTicket;

    public AttachmentService(TicketAccessService access, AttachmentRepository attachments,
                             AttachmentContentRepository contents, TicketRepository tickets, MalwareScanner scanner,
                             AuditLog audit, Clock clock,
                             @Value("${securedesk.upload.max-size:10MB}") DataSize maxSize,
                             @Value("${securedesk.upload.max-per-ticket:10}") int maxPerTicket) {
        this.access = access;
        this.attachments = attachments;
        this.contents = contents;
        this.tickets = tickets;
        this.scanner = scanner;
        this.audit = audit;
        this.clock = clock;
        this.maxBytes = maxSize.toBytes();
        this.maxPerTicket = maxPerTicket;
    }

    @Transactional
    public TicketDtos.AttachmentView uploadToOwnTicket(UUID ticketId, MultipartFile file) {
        Ticket ticket = access.ownTicket(ticketId);
        TicketService.requireOpen(ticket);
        return store(ticket, file);
    }

    @Transactional
    public TicketDtos.AttachmentView uploadToQueueTicket(UUID ticketId, MultipartFile file) {
        return store(access.queueTicket(ticketId), file);
    }

    public Download downloadFromOwnTicket(UUID ticketId, UUID attachmentId) {
        return load(access.ownTicket(ticketId), attachmentId);
    }

    public Download downloadFromQueueTicket(UUID ticketId, UUID attachmentId) {
        return load(access.queueTicket(ticketId), attachmentId);
    }

    private TicketDtos.AttachmentView store(Ticket ticket, MultipartFile file) {
        if (attachments.countByTicketId(ticket.getId()) >= maxPerTicket) {
            throw reject(ticket, "too_many", HttpStatus.CONFLICT, "This ticket already has the maximum number of attachments.");
        }
        if (file == null || file.isEmpty()) {
            throw reject(ticket, "empty", HttpStatus.BAD_REQUEST, "The file is empty.");
        }
        if (file.getSize() > maxBytes) {
            throw reject(ticket, "too_large", HttpStatus.CONTENT_TOO_LARGE, "The file is too large.");
        }
        byte[] bytes;
        try {
            bytes = file.getBytes();
        } catch (IOException e) {
            throw reject(ticket, "unreadable", HttpStatus.BAD_REQUEST, "The file could not be read.");
        }
        String name = safeName(file.getOriginalFilename());
        ContentInspector.Type type = ContentInspector.detect(bytes)
                .orElseThrow(() -> reject(ticket, "type_not_allowed", HttpStatus.UNSUPPORTED_MEDIA_TYPE,
                        "Only PNG, JPEG, PDF and plain-text files can be attached."));
        if (!type.extensions.contains(extension(name))) {
            throw reject(ticket, "extension_mismatch", HttpStatus.UNSUPPORTED_MEDIA_TYPE,
                    "The file name does not match its content.");
        }
        if (type == ContentInspector.Type.PDF && ContentInspector.hasActivePdfContent(bytes)) {
            throw reject(ticket, "active_content", HttpStatus.UNSUPPORTED_MEDIA_TYPE,
                    "PDF files with scripts or embedded files cannot be attached.");
        }
        MalwareScanner.Verdict verdict = scanner.scan(bytes);
        if (verdict == MalwareScanner.Verdict.INFECTED) {
            throw reject(ticket, "malware", HttpStatus.UNSUPPORTED_MEDIA_TYPE, "The file was refused by the virus scanner.");
        }
        String sha256 = sha256(bytes);
        Attachment attachment = attachments.save(new Attachment(ticket.getId(), CurrentUser.require().id(), name,
                type.mediaType, bytes.length, sha256, clock.instant()));
        contents.save(new AttachmentContent(attachment.getId(), bytes));
        ticket.touch(clock.instant());
        tickets.save(ticket);
        audit.event(AuditType.ATTACHMENT_UPLOADED).target("attachment", attachment.getId())
                .detail("ticket_id", ticket.getId()).detail("media_type", type.mediaType)
                .detail("size", bytes.length).detail("sha256", sha256)
                .detail("scan", verdict.name().toLowerCase(Locale.ROOT)).write();
        return new TicketDtos.AttachmentView(attachment.getId(), name, type.mediaType, bytes.length,
                null, attachment.getCreatedAt());
    }

    private Download load(Ticket ticket, UUID attachmentId) {
        Attachment attachment = access.attachmentOf(ticket, attachmentId);
        AttachmentContent content = contents.findById(attachment.getId()).orElseThrow(ApiException::notFound);
        audit.event(AuditType.ATTACHMENT_DOWNLOADED).target("attachment", attachment.getId())
                .detail("ticket_id", ticket.getId()).write();
        return new Download(attachment, content.getContent());
    }

    private ApiException reject(Ticket ticket, String reason, HttpStatus status, String message) {
        audit.event(AuditType.UPLOAD_REJECTED).outcome(Outcome.FAILURE).target("ticket", ticket.getId())
                .detail("reason", reason).write();
        return new ApiException(status, "upload_rejected", message);
    }

    /**
     * The uploaded name, for display only: the last path segment, NFC, letters, digits and a few
     * punctuation marks, at most 120 characters. The stored content is keyed by a random id.
     */
    static String safeName(String original) {
        String name = original == null ? "" : original;
        name = name.substring(Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\')) + 1);
        name = Normalizer.normalize(name, Normalizer.Form.NFC)
                .replaceAll("[^\\p{L}\\p{N} ._()-]", "_")
                .replaceAll("\\s+", " ")
                .strip();
        while (name.startsWith(".")) {
            name = name.substring(1);
        }
        if (name.length() > 120) {
            String extension = extension(name);
            name = name.substring(0, 119 - extension.length()) + "." + extension;
        }
        return name.isBlank() ? "attachment" : name;
    }

    static String extension(String name) {
        int dot = name.lastIndexOf('.');
        return dot < 0 ? "" : name.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    private static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
