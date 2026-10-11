package nl.fontys.securedesk.audit;

import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * The event-specific fields of an audit event, with the forbidden-field policy of SC-09 enforced
 * at the only place such a field could enter: passwords, codes, tokens, session identifiers,
 * ticket content and attachment content never reach the audit stream, and a test fails the build
 * if any of these keys is accepted.
 *
 * <p>Keys are sorted, so the canonical form, and with it the hash, does not depend on the order
 * in which the caller added them.
 */
public final class AuditDetails {

    static final int MAX_KEYS = 16;
    static final int MAX_VALUE_LENGTH = 120;

    private static final Pattern KEY = Pattern.compile("[a-z][a-z0-9_]{0,31}");

    /** Exact keys that would carry a credential, a token or content. */
    static final Set<String> FORBIDDEN_KEYS = Set.of(
            "password", "new_password", "current_password", "passwd", "pwd", "passphrase",
            "secret", "totp_secret", "otp", "code", "totp", "recovery_code", "pin",
            "token", "csrf", "csrf_token", "access_token", "refresh_token", "api_key", "key",
            "cookie", "session", "session_id", "jsessionid", "authorization",
            "description", "body", "comment", "content", "text", "title", "resolution", "message",
            "filename", "file", "email", "phone");

    /** Substrings that are never acceptable anywhere in a key. */
    static final Set<String> FORBIDDEN_FRAGMENTS = Set.of("password", "passwd", "secret", "token", "cookie");

    private final TreeMap<String, String> values = new TreeMap<>();

    public AuditDetails put(String key, Object value) {
        if (!KEY.matcher(key).matches()) {
            throw new IllegalArgumentException("audit detail key not allowed: " + key);
        }
        String lower = key.toLowerCase(Locale.ROOT);
        if (FORBIDDEN_KEYS.contains(lower)) {
            throw new IllegalArgumentException("forbidden audit detail key: " + key);
        }
        for (String fragment : FORBIDDEN_FRAGMENTS) {
            if (lower.contains(fragment)) {
                throw new IllegalArgumentException("forbidden audit detail key: " + key);
            }
        }
        if (values.size() >= MAX_KEYS && !values.containsKey(key)) {
            throw new IllegalArgumentException("too many audit details");
        }
        String text = String.valueOf(value);
        if (text.length() > MAX_VALUE_LENGTH) {
            text = text.substring(0, MAX_VALUE_LENGTH) + "...";
        }
        values.put(key, text);
        return this;
    }

    public boolean isEmpty() {
        return values.isEmpty();
    }

    Map<String, String> asMap() {
        return Collections.unmodifiableMap(values);
    }

    String toJson() {
        return CanonicalJson.write(values);
    }
}
