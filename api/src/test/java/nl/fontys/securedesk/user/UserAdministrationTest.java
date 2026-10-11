package nl.fontys.securedesk.user;

import com.jayway.jsonpath.JsonPath;
import nl.fontys.securedesk.audit.AuditEvent;
import nl.fontys.securedesk.audit.AuditType;
import nl.fontys.securedesk.support.Browser;
import nl.fontys.securedesk.support.IntegrationTest;
import nl.fontys.securedesk.support.Sessions;
import nl.fontys.securedesk.ticket.Ticket;
import nl.fontys.securedesk.ticket.TicketRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.AbstractMockHttpServletRequestBuilder;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

/** UC-05 and SR-10: account administration, its guard rails, and erasure. */
class UserAdministrationTest extends IntegrationTest {

    @Autowired
    TicketRepository tickets;

    private MvcResult asAdmin(AppUser admin, AbstractMockHttpServletRequestBuilder<?> request) throws Exception {
        return mvc.perform(request.with(Sessions.signedIn(reload(admin), clock.instant()))).andReturn();
    }

    private static String body(MvcResult result) {
        return new String(result.getResponse().getContentAsByteArray(), StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("an administrator cannot disable, demote or erase their own account")
    void notOnYourself() throws Exception {
        AppUser admin = createUser("admin", Role.ADMIN, true);
        MvcResult disable = asAdmin(admin, put("/api/admin/users/" + admin.getId() + "/enabled")
                .contentType(MediaType.APPLICATION_JSON).content("{\"enabled\":false}"));
        MvcResult demote = asAdmin(admin, put("/api/admin/users/" + admin.getId() + "/role")
                .contentType(MediaType.APPLICATION_JSON).content("{\"role\":\"REQUESTER\"}"));
        MvcResult erase = asAdmin(admin, delete("/api/admin/users/" + admin.getId()));
        assertThat(disable.getResponse().getStatus()).isEqualTo(409);
        assertThat(demote.getResponse().getStatus()).isEqualTo(409);
        assertThat(erase.getResponse().getStatus()).isEqualTo(409);
        assertThat(reload(admin).isEnabled()).isTrue();
    }

    @Test
    @DisplayName("the factor can be made optional for a requester, never for an agent or administrator")
    void mfaAlwaysForPrivilegedRoles() throws Exception {
        AppUser admin = createUser("admin", Role.ADMIN, true);
        AppUser agent = createUser("agent", Role.AGENT, true);
        AppUser requester = createUser("req", Role.REQUESTER, true);
        MvcResult forAgent = asAdmin(admin, put("/api/admin/users/" + agent.getId() + "/mfa-required")
                .contentType(MediaType.APPLICATION_JSON).content("{\"required\":false}"));
        assertThat(forAgent.getResponse().getStatus()).isEqualTo(400);
        MvcResult forRequester = asAdmin(admin, put("/api/admin/users/" + requester.getId() + "/mfa-required")
                .contentType(MediaType.APPLICATION_JSON).content("{\"required\":false}"));
        assertThat(forRequester.getResponse().getStatus()).isEqualTo(200);
        assertThat(reload(requester).mfaMandatory()).isFalse();
        assertThat(events(AuditType.MFA_REQUIREMENT_CHANGED)).last().matches(AuditEvent::isAlert);
    }

    @Test
    @DisplayName("a disabled account cannot sign in and its open sessions end")
    void disableEndsAccess() throws Exception {
        AppUser admin = createUser("admin", Role.ADMIN, true);
        AppUser requester = createUser("leaver", Role.REQUESTER, false);
        Browser leaver = new Browser(mvc);
        login(leaver, requester, PASSWORD);
        assertThat(leaver.get("/api/tickets").getResponse().getStatus()).isEqualTo(200);

        asAdmin(admin, put("/api/admin/users/" + requester.getId() + "/enabled")
                .contentType(MediaType.APPLICATION_JSON).content("{\"enabled\":false}"));

        assertThat(leaver.get("/api/tickets").getResponse().getStatus()).isEqualTo(401);
        assertThat(login(new Browser(mvc), requester, PASSWORD).getResponse().getStatus()).isEqualTo(401);
        assertThat(events(AuditType.USER_DISABLED)).last().matches(AuditEvent::isAlert);
    }

    @Test
    @DisplayName("erasure removes personal data, credentials and the user's tickets")
    void erasure() throws Exception {
        AppUser admin = createUser("admin", Role.ADMIN, true);
        AppUser requester = createUser("erase", Role.REQUESTER, false);
        Ticket ticket = tickets.save(new Ticket(requester.getId(), 1L, "Mine", "Personal details", clock.instant()));

        MvcResult erased = asAdmin(admin, delete("/api/admin/users/" + requester.getId()));
        assertThat(erased.getResponse().getStatus()).isEqualTo(200);
        assertThat(JsonPath.<Boolean>read(body(erased), "$.erased")).isTrue();

        AppUser after = reload(requester);
        assertThat(after.getUsername()).startsWith("erased-");
        assertThat(after.getEmail()).isNull();
        assertThat(after.getPasswordRecord()).isNull();
        assertThat(tickets.findById(ticket.getId())).isEmpty();
        assertThat(events(AuditType.USER_ERASED)).last().extracting(AuditEvent::getDetails).asString()
                .contains("\"tickets_deleted\":\"1\"");
    }

    @Test
    @DisplayName("usernames are unique and validated")
    void usernameRules() throws Exception {
        AppUser admin = createUser("admin", Role.ADMIN, true);
        AppUser existing = createUser("taken", Role.REQUESTER, true);
        MvcResult duplicate = asAdmin(admin, post("/api/admin/users").contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"" + existing.getUsername() + "\",\"displayName\":\"X\",\"role\":\"REQUESTER\"}"));
        assertThat(duplicate.getResponse().getStatus()).isEqualTo(409);
        MvcResult invalid = asAdmin(admin, post("/api/admin/users").contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"<b>x</b>\",\"displayName\":\"X\",\"role\":\"REQUESTER\"}"));
        assertThat(invalid.getResponse().getStatus()).isEqualTo(400);
        assertThat(JsonPath.<java.util.List<String>>read(body(invalid), "$.fields")).contains("username");
    }
}
