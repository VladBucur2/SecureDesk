package nl.fontys.securedesk.common;

import java.text.Normalizer;

/**
 * Server-side clean-up of free text before it is stored (SC-04). Text is stored and served as
 * text and escaped where it is displayed; this only removes what has no business in a ticket:
 * control characters other than line feed and tab, and the bidirectional overrides that can make
 * text read differently from what it is. Line endings become \n, and Unicode is NFC.
 */
public final class TextSanitizer {

    private TextSanitizer() {
    }

    public static String clean(String input) {
        if (input == null) {
            return null;
        }
        String text = Normalizer.normalize(input, Normalizer.Form.NFC)
                .replace("\r\n", "\n")
                .replace('\r', '\n');
        StringBuilder out = new StringBuilder(text.length());
        text.codePoints().forEach(cp -> {
            boolean control = Character.getType(cp) == Character.CONTROL && cp != '\n' && cp != '\t';
            boolean bidiOverride = (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069);
            if (!control && !bidiOverride) {
                out.appendCodePoint(cp);
            }
        });
        return out.toString().strip();
    }

    /** For single-line fields such as a title or a category name: whitespace runs become one space. */
    public static String cleanLine(String input) {
        String text = clean(input);
        return text == null ? null : text.replaceAll("\\s+", " ");
    }
}
