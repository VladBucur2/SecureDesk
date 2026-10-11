package nl.fontys.securedesk.auth;

import com.jayway.jsonpath.JsonPath;
import nl.fontys.securedesk.audit.AuditEvent;
import nl.fontys.securedesk.audit.AuditType;
import nl.fontys.securedesk.crypto.Argon2id;
import nl.fontys.securedesk.crypto.Pepper;
import nl.fontys.securedesk.support.Browser;
import nl.fontys.securedesk.support.IntegrationTest;
import nl.fontys.securedesk.user.AppUser;
import nl.fontys.securedesk.user.Role;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * The test cases of the mfa-poc (BoK 6.1.5), re-run against SecureDesk as regression tests
 * (6.1.8), plus the parts SecureDesk adds: the pepper, temporary passwords, step-up and the
 * security stamp. Case numbers refer to 6.1.5.
 */
class AuthenticationFlowTest extends IntegrationTest {

    @Autowired
    Pepper pepper;

    @Test
    @DisplayName("enrolment: the factor is switched on only after a confirmed code; ten recovery codes, shown once")
    void enrolment() throws Exception {
        AppUser agent = createUser("agent", Role.AGENT, true);
        Enrolled enrolled = enrol(agent);

        assertThat(enrolled.recoveryCodes()).hasSize(10).allMatch(c -> c.matches("[A-Z2-7]{4}-[A-Z2-7]{4}"));
        assertThat(reload(agent).isMfaEnabled()).isTrue();
        assertThat(reload(agent).getTotpSecret()).startsWith("totp:k1:").doesNotContain(enrolled.secret());
        assertThat(events(AuditType.MFA_ENROL_START, agent)).hasSize(1);
        assertThat(events(AuditType.MFA_ENROL_CONFIRM, agent)).hasSize(1);
        assertThat(events(AuditType.LOGIN_COMPLETE, agent)).last()
                .extracting(AuditEvent::getDetails).asString().contains("\"factors\":\"2\"");
    }

    @Test
    @DisplayName("case 1: two factors for an agent; a requester without the requirement signs in with one and is refused admin pages")
    void case1TwoFactorsAndOne() throws Exception {
        Enrolled agent = enrolled(Role.AGENT);
        assertThat(agent.browser().get("/api/queue").getResponse().getStatus()).isEqualTo(200);

        AppUser requester = createUser("requester", Role.REQUESTER, false);
        Browser browser = new Browser(mvc);
        assertThat(stage(login(browser, requester, PASSWORD))).isEqualTo("AUTHENTICATED");
        assertThat(browser.get("/api/tickets").getResponse().getStatus()).isEqualTo(200);
        assertThat(browser.get("/api/admin/users").getResponse().getStatus()).isEqualTo(403);
        assertThat(events(AuditType.LOGIN_COMPLETE, requester)).last()
                .extracting(AuditEvent::getDetails).asString().contains("\"factors\":\"1\"");
        assertThat(events(AuditType.AUTHZ_DENIED, requester)).isNotEmpty();
    }

    @Test
    @DisplayName("case 2: a wrong code is refused and the session stays at the code stage")
    void case2WrongCode() throws Exception {
        AppUser user = createUser("agent", Role.AGENT, true);
        String secret = enrol(user).secret();
        nextStep();
        Browser browser = new Browser(mvc);
        login(browser, user, PASSWORD);

        MvcResult wrong = browser.postJson("/api/auth/mfa", "{\"code\":\"000000\"}");
        assertThat(wrong.getResponse().getStatus()).isEqualTo(400);
        assertThat(error(wrong)).isEqualTo("invalid_code");
        assertThat(browser.refresh()).isEqualTo("MFA");

        MvcResult right = browser.postJson("/api/auth/mfa", "{\"code\":\"" + code(secret) + "\"}");
        assertThat(stage(right)).isEqualTo("AUTHENTICATED");
    }

    @Test
    @DisplayName("case 3: a session that passed only the password reaches nothing")
    void case3PendingSessionHasNoAuthority() throws Exception {
        AppUser user = createUser("admin", Role.ADMIN, true);
        enrol(user);
        nextStep();
        Browser browser = new Browser(mvc);
        assertThat(stage(login(browser, user, PASSWORD))).isEqualTo("MFA");

        assertThat(browser.get("/api/admin/users").getResponse().getStatus()).isEqualTo(401);
        assertThat(browser.get("/api/categories").getResponse().getStatus()).isEqualTo(401);
        assertThat(browser.postJson("/api/auth/reauth", "{\"code\":\"123456\"}").getResponse().getStatus())
                .isEqualTo(401);
        assertThat(events(AuditType.LOGIN_COMPLETE, user)).hasSize(1);   // the enrolment only
    }

    @Test
    @DisplayName("case 4: a code works once, even inside its own window")
    void case4CodeWorksOnce() throws Exception {
        AppUser user = createUser("agent", Role.AGENT, true);
        String secret = enrol(user).secret();
        nextStep();
        String code = code(secret);

        Browser first = new Browser(mvc);
        login(first, user, PASSWORD);
        assertThat(stage(first.postJson("/api/auth/mfa", "{\"code\":\"" + code + "\"}"))).isEqualTo("AUTHENTICATED");

        Browser second = new Browser(mvc);
        login(second, user, PASSWORD);
        MvcResult replay = second.postJson("/api/auth/mfa", "{\"code\":\"" + code + "\"}");
        assertThat(replay.getResponse().getStatus()).isEqualTo(400);
    }

    @Test
    @DisplayName("cases 5 to 7: one step back is accepted; three steps back and two minutes ahead are not")
    void cases5To7Window() throws Exception {
        AppUser user = createUser("agent", Role.AGENT, true);
        String secret = enrol(user).secret();
        clock.advance(Duration.ofMinutes(5));

        Browser previous = new Browser(mvc);
        login(previous, user, PASSWORD);
        String thirtySecondsAgo = codeAt(secret, clock.instant().minusSeconds(30));
        assertThat(stage(previous.postJson("/api/auth/mfa", "{\"code\":\"" + thirtySecondsAgo + "\"}")))
                .isEqualTo("AUTHENTICATED");

        clock.advance(Duration.ofMinutes(5));
        Browser old = new Browser(mvc);
        login(old, user, PASSWORD);
        String ninetySecondsAgo = codeAt(secret, clock.instant().minusSeconds(90));
        assertThat(old.postJson("/api/auth/mfa", "{\"code\":\"" + ninetySecondsAgo + "\"}").getResponse().getStatus())
                .isEqualTo(400);
        String twoMinutesAhead = codeAt(secret, clock.instant().plusSeconds(120));
        assertThat(old.postJson("/api/auth/mfa", "{\"code\":\"" + twoMinutesAhead + "\"}").getResponse().getStatus())
                .isEqualTo(400);
    }

    @Test
    @DisplayName("case 8: ten wrong codes lock the account, with growing delays; the correct password is refused until the lock ends")
    void case8Lockout() throws Exception {
        AppUser user = createUser("admin", Role.ADMIN, true);
        String secret = enrol(user).secret();
        nextStep();
        Browser browser = new Browser(mvc);
        login(browser, user, PASSWORD);
        sleeper.clear();

        for (int attempt = 1; attempt <= 9; attempt++) {
            MvcResult wrong = browser.postJson("/api/auth/mfa", "{\"code\":\"000000\"}");
            assertThat(wrong.getResponse().getStatus()).as("attempt %d", attempt).isEqualTo(400);
        }
        MvcResult tenth = browser.postJson("/api/auth/mfa", "{\"code\":\"000000\"}");
        assertThat(tenth.getResponse().getStatus()).isEqualTo(401);
        assertThat(browser.session()).as("the lockout ends the session").isNull();

        // the delay before each attempt grows with the failures counted so far: 0, 1, 2, 4, 8 seconds
        assertThat(sleeper.delays()).containsExactly(Duration.ZERO, Duration.ofSeconds(1), Duration.ofSeconds(2),
                Duration.ofSeconds(4), Duration.ofSeconds(8), Duration.ofSeconds(8), Duration.ofSeconds(8),
                Duration.ofSeconds(8), Duration.ofSeconds(8), Duration.ofSeconds(8));
        assertThat(events(AuditType.ACCOUNT_LOCKED, user)).hasSize(1).allMatch(AuditEvent::isAlert);

        // the token of the ended session is useless (the 403 of attempt 11 in the PoC)
        MvcResult afterLock = browser.postJsonWithCurrentToken("/api/auth/mfa", "{\"code\":\"000000\"}");
        assertThat(afterLock.getResponse().getStatus()).isEqualTo(403);

        Browser fresh = new Browser(mvc);
        MvcResult blocked = login(fresh, user, PASSWORD);
        assertThat(blocked.getResponse().getStatus()).isEqualTo(401);
        assertThat(events(AuditType.LOGIN_BLOCKED, user)).isNotEmpty();

        clock.advance(Duration.ofMinutes(16));
        Browser later = new Browser(mvc);
        assertThat(stage(login(later, user, PASSWORD))).isEqualTo("MFA");
        assertThat(stage(later.postJson("/api/auth/mfa", "{\"code\":\"" + code(secret) + "\"}"))).isEqualTo("AUTHENTICATED");
    }

    @Test
    @DisplayName("a correct password does not reset the failure count: codes cannot be guessed nine at a time")
    void passwordDoesNotResetCodeFailures() throws Exception {
        AppUser user = createUser("agent", Role.AGENT, true);
        enrol(user);
        nextStep();
        for (int round = 0; round < 2; round++) {
            Browser browser = new Browser(mvc);
            login(browser, user, PASSWORD);
            for (int attempt = 0; attempt < 5; attempt++) {
                browser.postJson("/api/auth/mfa", "{\"code\":\"000000\"}");
            }
        }
        assertThat(login(new Browser(mvc), user, PASSWORD).getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    @DisplayName("case 9: a recovery code is accepted once, raises an alert, and records the method")
    void case9RecoveryCodeOnce() throws Exception {
        AppUser user = createUser("admin", Role.ADMIN, true);
        Enrolled enrolled = enrol(user);
        String recovery = enrolled.recoveryCodes().get(0).toLowerCase();   // case and dash do not matter

        nextStep();
        Browser first = new Browser(mvc);
        login(first, user, PASSWORD);
        assertThat(stage(first.postJson("/api/auth/mfa", "{\"code\":\"" + recovery + "\"}"))).isEqualTo("AUTHENTICATED");
        assertThat(events(AuditType.MFA_RECOVERY_USED, user)).hasSize(1).allMatch(AuditEvent::isAlert);
        assertThat(events(AuditType.MFA_VERIFY, user)).last()
                .extracting(AuditEvent::getDetails).asString().contains("recovery_code");

        Browser second = new Browser(mvc);
        login(second, user, PASSWORD);
        assertThat(second.postJson("/api/auth/mfa", "{\"code\":\"" + recovery + "\"}").getResponse().getStatus())
                .isEqualTo(400);
    }

    @Test
    @DisplayName("case 12: an administrator resets a factor; the user's session ends and the next sign-in enrols a new secret")
    void case12MfaReset() throws Exception {
        Enrolled admin = enrolled(Role.ADMIN);
        AppUser agent = createUser("agent", Role.AGENT, true);
        Enrolled agentEnrolment = enrol(agent);

        MvcResult reset = admin.browser().postJson("/api/admin/users/" + agent.getId() + "/mfa-reset", "{}");
        assertThat(reset.getResponse().getStatus()).isEqualTo(200);
        assertThat(events(AuditType.MFA_RESET)).last().matches(AuditEvent::isAlert)
                .extracting(AuditEvent::getTargetId).isEqualTo(agent.getId().toString());

        assertThat(agentEnrolment.browser().get("/api/queue").getResponse().getStatus())
                .as("the agent's session ends at its next request").isEqualTo(401);
        assertThat(events(AuditType.SESSION_REVOKED, agent)).isNotEmpty();

        nextStep();
        Browser again = new Browser(mvc);
        assertThat(stage(login(again, agent, PASSWORD))).isEqualTo("ENROL");
        String newSecret = JsonPath.read(Browser.body(again.get("/api/auth/enrol")), "$.secret");
        assertThat(newSecret).isNotEqualTo(agentEnrolment.secret());
        MvcResult oldGenerator = again.postJson("/api/auth/enrol", "{\"code\":\"" + code(agentEnrolment.secret()) + "\"}");
        assertThat(oldGenerator.getResponse().getStatus()).isEqualTo(400);
    }

    @Test
    @DisplayName("an unknown username and a wrong password get the same answer, and the unknown name is not logged")
    void noAccountEnumeration() throws Exception {
        AppUser user = createUser("requester", Role.REQUESTER, false);
        MvcResult wrongPassword = login(new Browser(mvc), user, "not the password at all");
        Browser stranger = new Browser(mvc);
        MvcResult unknown = stranger.postJson("/api/auth/login",
                "{\"username\":\"my secret passphrase typed here\",\"password\":\"x\"}");

        assertThat(unknown.getResponse().getStatus()).isEqualTo(wrongPassword.getResponse().getStatus()).isEqualTo(401);
        assertThat(JsonPath.<String>read(Browser.body(unknown), "$.message"))
                .isEqualTo(JsonPath.<String>read(Browser.body(wrongPassword), "$.message"));
        assertThat(auditEvents.search("LOGIN_PASSWORD", null, null, null, null, false,
                org.springframework.data.domain.PageRequest.of(0, 50)).getContent())
                .noneMatch(e -> e.getActor().contains("passphrase") || e.getDetails().contains("passphrase"));
    }

    @Test
    @DisplayName("a temporary password must be replaced, then a factor enrolled, before anything else")
    void temporaryPasswordFlow() throws Exception {
        Enrolled admin = enrolled(Role.ADMIN);
        String username = "newagent-" + System.nanoTime() % 100000;
        MvcResult created = admin.browser().postJson("/api/admin/users",
                "{\"username\":\"" + username + "\",\"displayName\":\"New Agent\",\"email\":\"n@example.test\",\"role\":\"AGENT\"}");
        assertThat(created.getResponse().getStatus()).isEqualTo(201);
        String temporary = JsonPath.read(Browser.body(created), "$.temporaryPassword");

        Browser browser = new Browser(mvc);
        MvcResult first = browser.postJson("/api/auth/login",
                "{\"username\":\"" + username + "\",\"password\":\"" + temporary + "\"}");
        assertThat(stage(first)).isEqualTo("PASSWORD_CHANGE");
        assertThat(browser.get("/api/queue").getResponse().getStatus()).isEqualTo(401);

        MvcResult tooShort = browser.postJson("/api/auth/password", "{\"newPassword\":\"short\"}");
        assertThat(tooShort.getResponse().getStatus()).isEqualTo(400);
        assertThat(error(tooShort)).isEqualTo("password_rejected");

        MvcResult changed = browser.postJson("/api/auth/password", "{\"newPassword\":\"a brand new long passphrase\"}");
        assertThat(stage(changed)).isEqualTo("ENROL");
        assertThat(Browser.body(created)).doesNotContain("passwordRecord");
    }

    @Test
    @DisplayName("the session id changes when the session becomes authenticated (no fixation)")
    void sessionIdRotates() throws Exception {
        AppUser user = createUser("agent", Role.AGENT, true);
        String secret = enrol(user).secret();
        nextStep();
        Browser browser = new Browser(mvc);
        browser.refresh();
        String anonymous = browser.sessionId();
        login(browser, user, PASSWORD);
        String pending = browser.sessionId();
        browser.postJson("/api/auth/mfa", "{\"code\":\"" + code(secret) + "\"}");
        String authenticated = browser.sessionId();

        assertThat(pending).isNotEqualTo(anonymous);
        assertThat(authenticated).isNotEqualTo(pending);
    }

    @Test
    @DisplayName("administrative changes need a recent authentication; a fresh code restores it")
    void stepUp() throws Exception {
        Enrolled admin = enrolled(Role.ADMIN);
        AppUser target = createUser("requester", Role.REQUESTER, true);

        clock.advance(Duration.ofMinutes(11));
        MvcResult refused = admin.browser().postJson("/api/admin/users/" + target.getId() + "/mfa-reset", "{}");
        assertThat(refused.getResponse().getStatus()).isEqualTo(403);
        assertThat(error(refused)).isEqualTo("reauth_required");

        MvcResult reauth = admin.browser().postJson("/api/auth/reauth", "{\"code\":\"" + code(admin.secret()) + "\"}");
        assertThat(reauth.getResponse().getStatus()).isEqualTo(204);
        MvcResult allowed = admin.browser().postJson("/api/admin/users/" + target.getId() + "/mfa-reset", "{}");
        assertThat(allowed.getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    @DisplayName("a role change ends the user's sessions; the next request is unauthenticated")
    void roleChangeRevokesSessions() throws Exception {
        Enrolled admin = enrolled(Role.ADMIN);
        AppUser agent = createUser("agent", Role.AGENT, true);
        Enrolled agentSession = enrol(agent);

        MvcResult changed = admin.browser().putJson("/api/admin/users/" + agent.getId() + "/role", "{\"role\":\"REQUESTER\"}");
        assertThat(changed.getResponse().getStatus()).isEqualTo(200);

        assertThat(agentSession.browser().get("/api/queue").getResponse().getStatus()).isEqualTo(401);
        assertThat(events(AuditType.USER_ROLE_CHANGED)).last().matches(AuditEvent::isAlert)
                .extracting(AuditEvent::getDetails).asString().contains("\"old_role\":\"AGENT\"", "\"new_role\":\"REQUESTER\"");
    }

    @Test
    @DisplayName("a state-changing request without the CSRF token is refused and audited")
    void csrfRequired() throws Exception {
        AppUser user = createUser("requester", Role.REQUESTER, false);
        MvcResult result = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"" + user.getUsername() + "\",\"password\":\"" + PASSWORD + "\"}")).andReturn();
        assertThat(result.getResponse().getStatus()).isEqualTo(403);
        assertThat(events(AuditType.CSRF_DENIED)).isNotEmpty();
    }

    @Test
    @DisplayName("a hash made under older parameters is upgraded at the next sign-in")
    void rehashOnLogin() throws Exception {
        AppUser user = createUser("requester", Role.REQUESTER, false);
        user.setPasswordRecord(pepper.sealPassword(user.getId(), oldRecord()));
        users.save(user);

        assertThat(stage(login(new Browser(mvc), user, PASSWORD))).isEqualTo("AUTHENTICATED");
        String upgraded = pepper.openPassword(user.getId(), reload(user).getPasswordRecord());
        assertThat(upgraded).startsWith("$argon2id$v=19$m=19456,t=2,p=1$");
        assertThat(events(AuditType.PASSWORD_REHASHED, user)).hasSize(1);
    }

    @Test
    @DisplayName("a password record copied from another row is detected as tampering and refused")
    void tamperedRecord() throws Exception {
        AppUser victim = createUser("admin", Role.ADMIN, true);
        AppUser mallory = createUser("requester", Role.REQUESTER, false);
        victim.setPasswordRecord(reload(mallory).getPasswordRecord());
        users.save(victim);

        assertThat(login(new Browser(mvc), victim, PASSWORD).getResponse().getStatus()).isEqualTo(401);
        List<AuditEvent> tampered = events(AuditType.CREDENTIAL_TAMPERED, victim);
        assertThat(tampered).hasSize(1).allMatch(AuditEvent::isAlert);
    }

    @Test
    @DisplayName("the user's own password change ends their other sessions but keeps this one")
    void ownPasswordChange() throws Exception {
        AppUser user = createUser("requester", Role.REQUESTER, false);
        Browser one = new Browser(mvc);
        Browser two = new Browser(mvc);
        login(one, user, PASSWORD);
        login(two, user, PASSWORD);

        MvcResult wrong = one.postJson("/api/account/password",
                "{\"currentPassword\":\"wrong\",\"newPassword\":\"another fine long passphrase\"}");
        assertThat(wrong.getResponse().getStatus()).isEqualTo(400);
        MvcResult changed = one.postJson("/api/account/password",
                "{\"currentPassword\":\"" + PASSWORD + "\",\"newPassword\":\"another fine long passphrase\"}");
        assertThat(changed.getResponse().getStatus()).isEqualTo(204);

        assertThat(one.get("/api/tickets").getResponse().getStatus()).isEqualTo(200);
        assertThat(two.get("/api/tickets").getResponse().getStatus()).isEqualTo(401);
    }

    private String oldRecord() {
        byte[] salt = new byte[16];
        new java.security.SecureRandom().nextBytes(salt);
        Argon2id.Params old = new Argon2id.Params(4096, 3, 1);
        byte[] hash = Argon2id.hash(PASSWORD.getBytes(java.nio.charset.StandardCharsets.UTF_8), salt, old, 32);
        return new nl.fontys.securedesk.crypto.StoredHash(old, salt, hash).format();
    }
}
