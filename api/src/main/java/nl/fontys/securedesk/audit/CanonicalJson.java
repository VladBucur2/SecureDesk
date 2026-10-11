package nl.fontys.securedesk.audit;

import java.util.Map;

/**
 * A deliberately small JSON writer for flat objects of strings and booleans. It is used instead
 * of Jackson for the audit stream because the hash chain needs one exact byte sequence per event:
 * fixed key order, fixed escaping, no configuration that could change between releases.
 *
 * <p>Log injection is prevented structurally (BoK 5.3.4): every value is a JSON string, and CR,
 * LF and every other control character are escaped, so a value can never start a new record.
 */
final class CanonicalJson {

    private CanonicalJson() {
    }

    /** Values must be String or Boolean; nested maps are written as nested objects. */
    static String write(Map<String, ?> fields) {
        StringBuilder out = new StringBuilder(256);
        writeObject(out, fields);
        return out.toString();
    }

    private static void writeObject(StringBuilder out, Map<String, ?> fields) {
        out.append('{');
        boolean first = true;
        for (Map.Entry<String, ?> entry : fields.entrySet()) {
            if (!first) {
                out.append(',');
            }
            first = false;
            string(out, entry.getKey());
            out.append(':');
            Object value = entry.getValue();
            if (value instanceof Boolean b) {
                out.append(b ? "true" : "false");
            } else if (value instanceof Map<?, ?> nested) {
                @SuppressWarnings("unchecked")
                Map<String, ?> typed = (Map<String, ?>) nested;
                writeObject(out, typed);
            } else {
                string(out, String.valueOf(value));
            }
        }
        out.append('}');
    }

    private static void string(StringBuilder out, String value) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20 || c == 0x7f || c == ' ' || c == ' ') {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }
}
