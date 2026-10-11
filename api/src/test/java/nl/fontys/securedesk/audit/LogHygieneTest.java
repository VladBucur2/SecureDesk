package nl.fontys.securedesk.audit;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import com.jayway.jsonpath.JsonPath;
import nl.fontys.securedesk.common.RequestContext;
import nl.fontys.securedesk.support.Browser;
import nl.fontys.securedesk.support.IntegrationTest;
import nl.fontys.securedesk.user.AppUser;
import nl.fontys.securedesk.user.Role;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * BoK 6.2.5: "the forbidden-field rule of SC-09 must cover every logger, not only the audit
 * stream". A whole sign-in with enrolment runs with the loggers that leaked in the PoC turned up
 * to TRACE; then everything that was written, to stdout and to the audit table, is searched for
 * every secret that passed through: the password, the stored records, the TOTP secret, the
 * recovery codes, the codes and the CSRF token.
 */
@ExtendWith(OutputCaptureExtension.class)
class LogHygieneTest extends IntegrationTest {

    @Autowired
    JdbcTemplate jdbc;

    @Test
    @DisplayName("no secret reaches any log or the audit trail, even with the dangerous loggers at TRACE")
    void noSecretsAnywhere(CapturedOutput output) throws Exception {
        List<String> noisy = List.of("org.hibernate.orm.jdbc.bind", "org.hibernate.SQL",
                "org.springframework.web", "org.springframework.security", "org.apache.coyote");
        noisy.forEach(name -> ((Logger) LoggerFactory.getLogger(name)).setLevel(Level.TRACE));
        List<String> secrets = new ArrayList<>();
        List<String> codes = new ArrayList<>();
        try {
            AppUser user = createUser("hygiene", Role.ADMIN, true);
            secrets.add(PASSWORD);
            secrets.add(reload(user).getPasswordRecord());

            Enrolled enrolled = enrol(user);
            secrets.add(enrolled.secret());
            secrets.add(reload(user).getTotpSecret());
            secrets.addAll(enrolled.recoveryCodes());

            nextStep();
            Browser browser = new Browser(mvc);
            login(browser, user, PASSWORD);
            String code = code(enrolled.secret());
            codes.add(code);
            secrets.add(JsonPath.read(Browser.body(browser.get("/api/auth/session")), "$.csrfToken"));
            browser.postJson("/api/auth/mfa", "{\"code\":\"" + code + "\"}");
            assertThat(browser.refresh()).isEqualTo("AUTHENTICATED");
        } finally {
            noisy.forEach(name -> ((Logger) LoggerFactory.getLogger(name)).setLevel(null));
        }

        String everything = output.getAll();
        List<String> details = jdbc.queryForList("select details from audit_event", String.class);
        List<String> actors = jdbc.queryForList("select actor from audit_event", String.class);
        for (String secret : secrets) {
            assertThat(secret).isNotBlank();
            assertThat(everything).as("stdout must not contain a secret").doesNotContain(secret);
            assertThat(details).as("audit details must not contain a secret").noneMatch(d -> d.contains(secret));
            assertThat(actors).noneMatch(a -> a.contains(secret));
        }
        // A six-digit code can occur by chance inside a hash, so it is looked for where it would leak.
        for (String code : codes) {
            assertThat(everything).doesNotContain("\"code\":\"" + code + "\"").doesNotContain("code=" + code);
        }
        assertThat(everything).as("the audit stream did run").contains("\"event\":\"LOGIN_COMPLETE\"");
    }

    @Test
    @DisplayName("the session field is a short hash, never the session id")
    void sessionIdIsHashed() {
        String id = "7F3C2A9B4E1D6C8A0B5F2E7D9C1A3B6E";
        String hash = RequestContext.hashSessionId(id);
        assertThat(hash).hasSize(12).matches("[0-9a-f]{12}").doesNotContainIgnoringCase(id.substring(0, 6));
    }
}
