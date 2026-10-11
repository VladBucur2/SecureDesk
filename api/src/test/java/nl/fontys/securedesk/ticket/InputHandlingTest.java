package nl.fontys.securedesk.ticket;

import nl.fontys.securedesk.common.TextSanitizer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for the server-side clean-up of text, names and content (SC-04, SC-05). */
class InputHandlingTest {

    @Test
    @DisplayName("control characters and bidirectional overrides are removed; line feeds and tabs stay")
    void sanitisesText() {
        String input = "line one\r\nline\u0000 two\u202Etxt.exe\u202C\tend\u0007";
        assertThat(TextSanitizer.clean(input)).isEqualTo("line one\nline twotxt.exe\tend");
        assertThat(TextSanitizer.cleanLine("  a\n\n  title  ")).isEqualTo("a title");
    }

    @Test
    @DisplayName("an uploaded name loses its path, odd characters and leading dots")
    void cleansFileNames() {
        assertThat(AttachmentService.safeName("../../etc/passwd")).isEqualTo("passwd");
        assertThat(AttachmentService.safeName("C:\\Users\\a\\report.pdf")).isEqualTo("report.pdf");
        assertThat(AttachmentService.safeName(".htaccess")).isEqualTo("htaccess");
        assertThat(AttachmentService.safeName("a<script>.txt")).isEqualTo("a_script_.txt");
        assertThat(AttachmentService.safeName(null)).isEqualTo("attachment");
        assertThat(AttachmentService.safeName("x".repeat(300) + ".log")).hasSize(120).endsWith(".log");
    }

    @Test
    @DisplayName("content types come from the bytes, not from the name or the client")
    void detectsByContent() {
        assertThat(ContentInspector.detect(new byte[] {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, 0})).contains(ContentInspector.Type.JPEG);
        assertThat(ContentInspector.detect("%PDF-1.4".getBytes(StandardCharsets.US_ASCII))).contains(ContentInspector.Type.PDF);
        assertThat(ContentInspector.detect("plain words".getBytes(StandardCharsets.UTF_8))).contains(ContentInspector.Type.TEXT);
        assertThat(ContentInspector.detect(new byte[] {'a', 0, 'b'})).isEmpty();
        assertThat(ContentInspector.detect(new byte[] {(byte) 0xC3, (byte) 0x28})).as("invalid UTF-8").isEmpty();
    }

    @Test
    @DisplayName("a LIKE search pattern is escaped")
    void escapesLike() {
        assertThat(TicketService.escapeLike("100%_a\\b")).isEqualTo("100\\%\\_a\\\\b");
    }
}
