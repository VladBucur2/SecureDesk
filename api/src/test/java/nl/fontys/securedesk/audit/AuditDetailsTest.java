package nl.fontys.securedesk.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The serialiser test of SC-09: if a forbidden field could enter the audit stream, the build
 * fails here. Values are JSON strings with every control character escaped, so a value cannot
 * start a record of its own (BoK 5.3.4, 6.2.4).
 */
class AuditDetailsTest {

    @ParameterizedTest
    @ValueSource(strings = {"password", "new_password", "secret", "totp_secret", "code", "otp", "token",
            "csrf_token", "cookie", "session_id", "authorization", "description", "body", "comment", "content",
            "title", "filename", "email", "my_password_hint", "api_token_id", "SessionId", "pass word"})
    @DisplayName("forbidden and malformed keys are refused")
    void refusesForbiddenKeys(String key) {
        assertThatThrownBy(() -> new AuditDetails().put(key, "x")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("every catalogue key the application uses is allowed")
    void allowsOperationalKeys() {
        AuditDetails details = new AuditDetails();
        for (String key : new String[] {"reason", "failed_count", "method", "factors", "old_role", "new_role",
                "path", "fields", "media_type", "size", "sha256", "scan", "ticket_id", "checked_up_to"}) {
            details.put(key, "v");
        }
        assertThat(details.asMap()).hasSize(14);
    }

    @Test
    @DisplayName("CR, LF and other control characters cannot break out of a value")
    void escapesInjection() {
        String json = new AuditDetails().put("path", "/x\r\n{\"event\":\"LOGIN_COMPLETE\"}\u0000").toJson();
        assertThat(json).doesNotContain("\n").doesNotContain("\r").doesNotContain("\u0000");
        assertThat(json).isEqualTo("{\"path\":\"/x\\r\\n{\\\"event\\\":\\\"LOGIN_COMPLETE\\\"}\\u0000\"}");
    }

    @Test
    @DisplayName("keys are sorted, so the canonical form does not depend on insertion order")
    void sortedKeys() {
        String a = new AuditDetails().put("b", 1).put("a", 2).toJson();
        String b = new AuditDetails().put("a", 2).put("b", 1).toJson();
        assertThat(a).isEqualTo(b).isEqualTo(CanonicalJson.write(Map.of("a", "2")).replace("}", ",\"b\":\"1\"}"));
    }

    @Test
    @DisplayName("long values are cut, so a detail cannot carry a document")
    void truncatesLongValues() {
        String json = new AuditDetails().put("path", "a".repeat(5000)).toJson();
        assertThat(json.length()).isLessThan(200);
    }
}
