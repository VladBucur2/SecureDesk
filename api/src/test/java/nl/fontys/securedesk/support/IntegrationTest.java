package nl.fontys.securedesk.support;

import com.jayway.jsonpath.JsonPath;
import nl.fontys.securedesk.audit.AuditEvent;
import nl.fontys.securedesk.audit.AuditEventRepository;
import nl.fontys.securedesk.audit.AuditType;
import nl.fontys.securedesk.auth.Base32;
import nl.fontys.securedesk.auth.TotpService;
import nl.fontys.securedesk.crypto.PasswordHasher;
import nl.fontys.securedesk.user.AppUser;
import nl.fontys.securedesk.user.AppUserRepository;
import nl.fontys.securedesk.user.Role;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Base class of the integration tests: the whole application in one process, an H2 database
 * migrated by the real Flyway scripts, and MockMvc in front, so every request passes the real
 * filter chain, CSRF check, method security and audit trail.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestSupport.class)
public abstract class IntegrationTest {

    protected static final String PASSWORD = "lantern orbit mosaic gravel";

    @Autowired
    protected MockMvc mvc;
    @Autowired
    protected MutableClock clock;
    @Autowired
    protected RecordingSleeper sleeper;
    @Autowired
    protected AppUserRepository users;
    @Autowired
    protected PasswordHasher hasher;
    @Autowired
    protected TotpService totp;
    @Autowired
    protected AuditEventRepository auditEvents;

    @BeforeEach
    void moveToFreshStep() {
        // Every test starts in a step of its own, a few seconds in, so codes from an earlier test
        // or a step boundary in the middle of a test cannot interfere.
        clock.advance(Duration.ofMinutes(20));
        long step = clock.instant().getEpochSecond() / TotpService.STEP_SECONDS;
        clock.set(Instant.ofEpochSecond(step * TotpService.STEP_SECONDS + 5));
        sleeper.clear();
    }

    // ---- accounts ------------------------------------------------------------------------------

    protected AppUser createUser(String prefix, Role role, boolean mfaRequired) {
        String username = prefix + "-" + UUID.randomUUID().toString().substring(0, 8);
        AppUser user = new AppUser(username, "Test " + prefix, username + "@example.test", role, clock.instant());
        user.setMfaRequired(mfaRequired);
        user.setPasswordRecord(hasher.newPasswordRecord(user.getId(), PASSWORD));
        return users.save(user);
    }

    protected AppUser reload(AppUser user) {
        return users.findById(user.getId()).orElseThrow();
    }

    // ---- signing in ----------------------------------------------------------------------------

    protected MvcResult login(Browser browser, AppUser user, String password) throws Exception {
        return browser.postJson("/api/auth/login",
                "{\"username\":\"" + user.getUsername() + "\",\"password\":\"" + password + "\"}");
    }

    /** First sign-in of an account that must enrol: password, enrolment. Returns the secret. */
    protected Enrolled enrol(AppUser user) throws Exception {
        Browser browser = new Browser(mvc);
        assertThat(stage(login(browser, user, PASSWORD))).isEqualTo("ENROL");
        String secret = JsonPath.read(Browser.body(browser.get("/api/auth/enrol")), "$.secret");
        MvcResult done = browser.postJson("/api/auth/enrol", "{\"code\":\"" + code(secret) + "\"}");
        assertThat(done.getResponse().getStatus()).isEqualTo(200);
        List<String> recovery = JsonPath.read(Browser.body(done), "$.recoveryCodes");
        assertThat(stage(done)).isEqualTo("AUTHENTICATED");
        return new Enrolled(browser, secret, recovery);
    }

    public record Enrolled(Browser browser, String secret, List<String> recoveryCodes) {
    }

    /** A complete sign-in with password and code, in a fresh step so the code is not a replay. */
    protected Browser signIn(AppUser user, String secret) throws Exception {
        nextStep();
        Browser browser = new Browser(mvc);
        assertThat(stage(login(browser, user, PASSWORD))).isEqualTo("MFA");
        MvcResult result = browser.postJson("/api/auth/mfa", "{\"code\":\"" + code(secret) + "\"}");
        assertThat(stage(result)).isEqualTo("AUTHENTICATED");
        return browser;
    }

    /** Enrols the account and returns a signed-in browser plus the secret. */
    protected Enrolled enrolled(Role role) throws Exception {
        return enrol(createUser(role.name().toLowerCase(), role, true));
    }

    protected String code(String secret) {
        return totp.generate(Base32.decode(secret), totp.currentStep(clock.instant()));
    }

    protected String codeAt(String secret, Instant at) {
        return totp.generate(Base32.decode(secret), totp.currentStep(at));
    }

    protected void nextStep() {
        clock.advance(Duration.ofSeconds(TotpService.STEP_SECONDS));
    }

    protected static String stage(MvcResult result) throws Exception {
        return JsonPath.read(Browser.body(result), "$.stage");
    }

    protected static String error(MvcResult result) throws Exception {
        return JsonPath.read(Browser.body(result), "$.error");
    }

    // ---- audit ---------------------------------------------------------------------------------

    protected List<AuditEvent> events(AuditType type) {
        return auditEvents.findByEventTypeOrderBySeqAsc(type.name());
    }

    protected List<AuditEvent> events(AuditType type, AppUser actor) {
        return events(type).stream().filter(e -> e.getActorId().equals(actor.getId().toString())).toList();
    }
}
