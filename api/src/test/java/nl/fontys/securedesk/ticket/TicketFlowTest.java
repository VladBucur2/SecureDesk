package nl.fontys.securedesk.ticket;

import com.jayway.jsonpath.JsonPath;
import nl.fontys.securedesk.audit.AuditEvent;
import nl.fontys.securedesk.audit.AuditType;
import nl.fontys.securedesk.support.IntegrationTest;
import nl.fontys.securedesk.support.Sessions;
import nl.fontys.securedesk.user.AppUser;
import nl.fontys.securedesk.user.Role;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.AbstractMockHttpServletRequestBuilder;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

/** UC-02 to UC-04 and the controls on them: SC-03 (projections, DTOs), SC-04 (input), SC-05 (uploads). */
class TicketFlowTest extends IntegrationTest {

    private AppUser requester;
    private AppUser agent;

    @BeforeEach
    void accounts() {
        requester = createUser("req", Role.REQUESTER, false);
        agent = createUser("agent", Role.AGENT, true);
    }

    private MvcResult as(AppUser user, AbstractMockHttpServletRequestBuilder<?> request) throws Exception {
        return mvc.perform(request.with(Sessions.signedIn(reload(user), clock.instant()))).andReturn();
    }

    private String fileTicket(String title) throws Exception {
        MvcResult created = as(requester, post("/api/tickets").contentType(MediaType.APPLICATION_JSON)
                .content("{\"categoryId\":1,\"title\":\"" + title + "\",\"description\":\"Details here.\"}"));
        assertThat(created.getResponse().getStatus()).isEqualTo(201);
        return JsonPath.read(body(created), "$.id");
    }

    private static String body(MvcResult result) {
        return new String(result.getResponse().getContentAsByteArray(), StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("a requester files a ticket; status and priority are not theirs to set")
    void fileTicket() throws Exception {
        String id = fileTicket("Printer jams");
        String view = body(as(requester, get("/api/tickets/" + id)));
        assertThat(JsonPath.<String>read(view, "$.status")).isEqualTo("NEW");
        assertThat(JsonPath.<String>read(view, "$.reference")).matches("SD-[0-9A-F]{8}");
        assertThat(events(AuditType.TICKET_CREATED)).last().extracting(AuditEvent::getTargetId).isEqualTo(id);
    }

    @Test
    @DisplayName("mass assignment: a requester body with status or requesterId is refused and audited with the field name")
    void massAssignmentRefused() throws Exception {
        MvcResult result = as(requester, post("/api/tickets").contentType(MediaType.APPLICATION_JSON)
                .content("{\"categoryId\":1,\"title\":\"x\",\"description\":\"y\",\"status\":\"CLOSED\"}"));
        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        assertThat(events(AuditType.INPUT_VALIDATION_FAILED)).last()
                .extracting(AuditEvent::getDetails).asString().contains("\"field\":\"status\"", "unknown_field");
    }

    @Test
    @DisplayName("internal notes reach agents only; the requester's response does not contain them at all")
    void internalNotesStayInternal() throws Exception {
        String id = fileTicket("VPN drops");
        as(agent, post("/api/queue/" + id + "/comments").contentType(MediaType.APPLICATION_JSON)
                .content("{\"body\":\"INTERNAL-ONLY: user is on the watch list\",\"internal\":true}"));
        as(agent, post("/api/queue/" + id + "/comments").contentType(MediaType.APPLICATION_JSON)
                .content("{\"body\":\"Could you try another network?\",\"internal\":false}"));

        String requesterView = body(as(requester, get("/api/tickets/" + id)));
        assertThat(requesterView).doesNotContain("INTERNAL-ONLY").doesNotContain("\"internal\"");
        assertThat(JsonPath.<List<Object>>read(requesterView, "$.comments")).hasSize(1);

        String agentView = body(as(agent, get("/api/queue/" + id)));
        assertThat(agentView).contains("INTERNAL-ONLY");
        assertThat(events(AuditType.COMMENT_ADDED)).allSatisfy(e -> assertThat(e.getDetails()).doesNotContain("watch list"));
    }

    @Test
    @DisplayName("an agent assigns and asks a question; the requester's reply puts the ticket back in progress")
    void agentWorkflow() throws Exception {
        String id = fileTicket("Need ERP access");
        MvcResult updated = as(agent, put("/api/queue/" + id).contentType(MediaType.APPLICATION_JSON)
                .content("{\"status\":\"WAITING_ON_REQUESTER\",\"priority\":\"HIGH\",\"assigneeId\":\"" + agent.getId()
                        + "\",\"resolution\":null}"));
        assertThat(updated.getResponse().getStatus()).isEqualTo(200);
        assertThat(events(AuditType.TICKET_UPDATED)).last().extracting(AuditEvent::getDetails).asString()
                .contains("status,priority,assignee");

        as(requester, post("/api/tickets/" + id + "/comments").contentType(MediaType.APPLICATION_JSON)
                .content("{\"body\":\"Here is the cost centre.\"}"));
        assertThat(JsonPath.<String>read(body(as(agent, get("/api/queue/" + id))), "$.status")).isEqualTo("IN_PROGRESS");
    }

    @Test
    @DisplayName("tickets can only be assigned to agents, and a closed ticket takes no more comments")
    void assignmentAndClosing() throws Exception {
        String id = fileTicket("Monitor flickers");
        MvcResult toRequester = as(agent, put("/api/queue/" + id).contentType(MediaType.APPLICATION_JSON)
                .content("{\"status\":\"IN_PROGRESS\",\"priority\":\"NORMAL\",\"assigneeId\":\"" + requester.getId()
                        + "\",\"resolution\":null}"));
        assertThat(toRequester.getResponse().getStatus()).isEqualTo(400);

        as(agent, put("/api/queue/" + id).contentType(MediaType.APPLICATION_JSON)
                .content("{\"status\":\"CLOSED\",\"priority\":\"NORMAL\",\"assigneeId\":null,\"resolution\":\"Cable replaced\"}"));
        MvcResult late = as(requester, post("/api/tickets/" + id + "/comments").contentType(MediaType.APPLICATION_JSON)
                .content("{\"body\":\"Thanks\"}"));
        assertThat(late.getResponse().getStatus()).isEqualTo(409);
    }

    @Test
    @DisplayName("queue search treats % and _ as text, not as wildcards")
    void searchIsEscaped() throws Exception {
        fileTicket("Disk is 100% full " + requester.getUsername());
        fileTicket("Disk is fine " + requester.getUsername());
        String result = body(as(agent, get("/api/queue").param("q", "100%")));
        List<String> titles = JsonPath.read(result, "$.items[*].title");
        assertThat(titles).isNotEmpty().allMatch(t -> t.contains("100%"));
        String wildcard = body(as(agent, get("/api/queue").param("q", "%").param("size", "50")));
        assertThat(JsonPath.<List<String>>read(wildcard, "$.items[*].title")).allMatch(t -> t.contains("%"));
    }

    // ---- uploads (SC-05) -------------------------------------------------------------------------

    private MvcResult upload(String ticketId, String name, byte[] content) throws Exception {
        return as(requester, multipart("/api/tickets/" + ticketId + "/attachments")
                .file(new MockMultipartFile("file", name, "application/octet-stream", content)));
    }

    @Test
    @DisplayName("a log file is stored under a random key and served only as a download, with a cleaned-up name")
    void uploadAndDownload() throws Exception {
        String id = fileTicket("App crashes");
        MvcResult uploaded = upload(id, "../../etc/app crash.log", "line one\nline two\n".getBytes(StandardCharsets.UTF_8));
        assertThat(uploaded.getResponse().getStatus()).isEqualTo(201);
        String attachmentId = JsonPath.read(body(uploaded), "$.id");
        assertThat(JsonPath.<String>read(body(uploaded), "$.name")).isEqualTo("app crash.log");

        MvcResult download = as(requester, get("/api/tickets/" + id + "/attachments/" + attachmentId));
        assertThat(download.getResponse().getStatus()).isEqualTo(200);
        assertThat(download.getResponse().getHeader("Content-Disposition")).startsWith("attachment;");
        assertThat(download.getResponse().getHeader("X-Content-Type-Options")).isEqualTo("nosniff");
        assertThat(download.getResponse().getContentType()).isEqualTo("text/plain;charset=UTF-8");
        assertThat(download.getResponse().getHeader("Content-Security-Policy")).contains("sandbox");
        assertThat(events(AuditType.ATTACHMENT_UPLOADED)).last().extracting(AuditEvent::getDetails).asString()
                .contains("\"scan\":\"not_scanned\"").doesNotContain("line one");
    }

    @Test
    @DisplayName("uploads are refused by content: wrong type, a name that lies about the content, active PDF content, size")
    void uploadsRefused() throws Exception {
        String id = fileTicket("Uploads");
        byte[] png = {(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0};
        byte[] exe = {'M', 'Z', (byte) 0x90, 0, 3, 0, 0, 0, 4, 0, 0, 0, (byte) 0xFF, (byte) 0xFF};
        byte[] html = "<html><script>alert(document.cookie)</script></html>".getBytes(StandardCharsets.UTF_8);
        byte[] pdf = "%PDF-1.7\n1 0 obj << /OpenAction 2 0 R >> endobj 2 0 obj << /S /JavaScript /JS (app.alert(1)) >>"
                .getBytes(StandardCharsets.ISO_8859_1);

        assertThat(upload(id, "screenshot.png", png).getResponse().getStatus()).isEqualTo(201);
        assertThat(upload(id, "setup.exe", exe).getResponse().getStatus()).isEqualTo(415);
        assertThat(upload(id, "picture.png", html).getResponse().getStatus()).as("HTML named .png").isEqualTo(415);
        assertThat(upload(id, "page.html", html).getResponse().getStatus()).as("text, but not .txt or .log").isEqualTo(415);
        assertThat(upload(id, "invoice.pdf", pdf).getResponse().getStatus()).isEqualTo(415);
        assertThat(upload(id, "empty.txt", new byte[0]).getResponse().getStatus()).isEqualTo(400);
        assertThat(upload(id, "huge.txt", new byte[10 * 1024 * 1024 + 1]).getResponse().getStatus()).isEqualTo(413);

        assertThat(events(AuditType.UPLOAD_REJECTED)).extracting(AuditEvent::getDetails)
                .anyMatch(d -> d.contains("type_not_allowed"))
                .anyMatch(d -> d.contains("extension_mismatch"))
                .anyMatch(d -> d.contains("active_content"))
                .anyMatch(d -> d.contains("too_large"));
    }
}
