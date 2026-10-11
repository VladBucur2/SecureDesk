package nl.fontys.securedesk.ticket;

import org.springframework.http.CacheControl;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.nio.charset.StandardCharsets;

/**
 * How an attachment leaves the API (UC-03): always as a download, never rendered in the
 * SecureDesk origin, with the type established at upload rather than any type the client claimed.
 * The CSP of the API (default-src 'none'; sandbox) applies to it as well, so even a browser that
 * ignored the disposition would run nothing from it.
 */
final class AttachmentResponses {

    private AttachmentResponses() {
    }

    static ResponseEntity<byte[]> download(AttachmentService.Download download) {
        Attachment attachment = download.attachment();
        MediaType type = MediaType.parseMediaType(attachment.getMediaType());
        if ("text".equals(type.getType())) {
            type = new MediaType(type, StandardCharsets.UTF_8);
        }
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(type);
        headers.setContentDisposition(ContentDisposition.attachment()
                .filename(attachment.getDisplayName(), StandardCharsets.UTF_8).build());
        headers.setContentLength(download.content().length);
        headers.set("X-Content-Type-Options", "nosniff");
        headers.setCacheControl(CacheControl.noStore());
        return ResponseEntity.ok().headers(headers).body(download.content());
    }
}
