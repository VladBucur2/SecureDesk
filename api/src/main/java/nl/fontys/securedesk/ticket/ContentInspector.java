package nl.fontys.securedesk.ticket;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Establishes what an upload really is from its bytes (SC-05). The client's Content-Type and the
 * file name are claims; the type allow-list is checked against the content, and the name's
 * extension must agree with what the content turned out to be, which refuses the simplest
 * polyglots such as a PNG named .html or an HTML file named .png.
 */
final class ContentInspector {

    enum Type {
        PNG("image/png", Set.of("png")),
        JPEG("image/jpeg", Set.of("jpg", "jpeg")),
        PDF("application/pdf", Set.of("pdf")),
        TEXT("text/plain", Set.of("txt", "log"));

        final String mediaType;
        final Set<String> extensions;

        Type(String mediaType, Set<String> extensions) {
            this.mediaType = mediaType;
            this.extensions = extensions;
        }
    }

    /**
     * PDF features that run or launch something when the file is opened. Refusing them is a
     * heuristic, not a scanner: names can be obfuscated. The malware-scan interface is the place
     * for the real thing (residual risk of MU-05, BoK 5.2.6).
     */
    private static final List<String> ACTIVE_PDF_CONTENT = List.of(
            "/JavaScript", "/JS ", "/JS(", "/JS<", "/Launch", "/EmbeddedFile", "/RichMedia");

    private static final byte[] PNG_MAGIC = {(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    private static final byte[] JPEG_MAGIC = {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF};
    private static final byte[] PDF_MAGIC = {'%', 'P', 'D', 'F', '-'};

    private ContentInspector() {
    }

    static Optional<Type> detect(byte[] data) {
        if (startsWith(data, PNG_MAGIC)) {
            return Optional.of(Type.PNG);
        }
        if (startsWith(data, JPEG_MAGIC)) {
            return Optional.of(Type.JPEG);
        }
        if (startsWith(data, PDF_MAGIC)) {
            return Optional.of(Type.PDF);
        }
        if (isPlainText(data)) {
            return Optional.of(Type.TEXT);
        }
        return Optional.empty();
    }

    static boolean hasActivePdfContent(byte[] data) {
        String latin = new String(data, StandardCharsets.ISO_8859_1);
        return ACTIVE_PDF_CONTENT.stream().anyMatch(latin::contains);
    }

    /** Valid UTF-8 with no control characters other than tab, line feed, carriage return and form feed. */
    private static boolean isPlainText(byte[] data) {
        try {
            String text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(data))
                    .toString();
            return text.chars().noneMatch(c -> c < 0x20 && c != '\t' && c != '\n' && c != '\r' && c != '\f');
        } catch (CharacterCodingException e) {
            return false;
        }
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }
}
