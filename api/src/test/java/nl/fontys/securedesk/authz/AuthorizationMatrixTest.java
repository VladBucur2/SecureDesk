package nl.fontys.securedesk.authz;

import nl.fontys.securedesk.support.IntegrationTest;
import nl.fontys.securedesk.support.Sessions;
import nl.fontys.securedesk.ticket.Attachment;
import nl.fontys.securedesk.ticket.AttachmentContent;
import nl.fontys.securedesk.ticket.AttachmentContentRepository;
import nl.fontys.securedesk.ticket.AttachmentRepository;
import nl.fontys.securedesk.ticket.CategoryRepository;
import nl.fontys.securedesk.ticket.Ticket;
import nl.fontys.securedesk.ticket.TicketRepository;
import nl.fontys.securedesk.user.AppUser;
import nl.fontys.securedesk.user.Role;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.request.AbstractMockHttpServletRequestBuilder;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;

/**
 * The proof that SC-03 works (BoK 5.2.3 B): every role against every endpoint, for a resource of
 * its own and for someone else's, asserting the expected 200, 401, 403 or 404. Requesters get 404
 * for another requester's ticket, never 403, so the status code does not reveal that it exists.
 * A new endpoint that is not in this table fails {@code everyEndpointIsInTheMatrix}.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthorizationMatrixTest extends IntegrationTest {

    enum Who { ANONYMOUS, REQUESTER_OWN, REQUESTER_OTHER, AGENT, ADMIN }

    /** One endpoint; {@code {t}} and {@code {a}} are the ticket and attachment of the principal's case. */
    record Endpoint(String name, HttpMethod method, String path, String body, Map<Who, Integer> expected) {
    }

    private static final int OK = 200;
    private static final int CREATED = 201;
    private static final int UNAUTHENTICATED = 401;
    private static final int FORBIDDEN = 403;
    private static final int NOT_FOUND = 404;

    @Autowired
    TicketRepository tickets;
    @Autowired
    AttachmentRepository attachments;
    @Autowired
    AttachmentContentRepository contents;
    @Autowired
    CategoryRepository categories;

    private AppUser requesterA;
    private AppUser requesterB;
    private AppUser agent;
    private AppUser admin;
    private AppUser target;
    private Ticket ticketA;
    private Ticket ticketB;
    private Attachment attachmentA;
    private Attachment attachmentB;

    @BeforeAll
    void fixtures() {
        requesterA = createUser("reqa", Role.REQUESTER, false);
        requesterB = createUser("reqb", Role.REQUESTER, false);
        agent = createUser("agent", Role.AGENT, true);
        admin = createUser("admin", Role.ADMIN, true);
        target = createUser("target", Role.REQUESTER, true);
        Long category = categories.findByActiveTrueOrderByNameAsc().get(0).getId();
        ticketA = tickets.save(new Ticket(requesterA.getId(), category, "A's ticket", "Belongs to A", clock.instant()));
        ticketB = tickets.save(new Ticket(requesterB.getId(), category, "B's ticket", "Belongs to B", clock.instant()));
        attachmentA = attach(ticketA, requesterA);
        attachmentB = attach(ticketB, requesterB);
    }

    private Attachment attach(Ticket ticket, AppUser owner) {
        byte[] content = "log line".getBytes(StandardCharsets.UTF_8);
        Attachment attachment = attachments.save(new Attachment(ticket.getId(), owner.getId(), "app.log", "text/plain",
                content.length, "0".repeat(64), clock.instant()));
        contents.save(new AttachmentContent(attachment.getId(), content));
        return attachment;
    }

    static List<Endpoint> endpoints() {
        Map<Who, Integer> requesterObject = Map.of(Who.ANONYMOUS, UNAUTHENTICATED, Who.REQUESTER_OWN, OK,
                Who.REQUESTER_OTHER, NOT_FOUND, Who.AGENT, FORBIDDEN, Who.ADMIN, FORBIDDEN);
        Map<Who, Integer> requesterOnly = Map.of(Who.ANONYMOUS, UNAUTHENTICATED, Who.REQUESTER_OWN, OK,
                Who.REQUESTER_OTHER, OK, Who.AGENT, FORBIDDEN, Who.ADMIN, FORBIDDEN);
        Map<Who, Integer> agentOnly = Map.of(Who.ANONYMOUS, UNAUTHENTICATED, Who.REQUESTER_OWN, FORBIDDEN,
                Who.REQUESTER_OTHER, FORBIDDEN, Who.AGENT, OK, Who.ADMIN, FORBIDDEN);
        Map<Who, Integer> adminOnly = Map.of(Who.ANONYMOUS, UNAUTHENTICATED, Who.REQUESTER_OWN, FORBIDDEN,
                Who.REQUESTER_OTHER, FORBIDDEN, Who.AGENT, FORBIDDEN, Who.ADMIN, OK);
        Map<Who, Integer> anyUser = Map.of(Who.ANONYMOUS, UNAUTHENTICATED, Who.REQUESTER_OWN, OK,
                Who.REQUESTER_OTHER, OK, Who.AGENT, OK, Who.ADMIN, OK);

        String ticketBody = "{\"categoryId\":1,\"title\":\"Printer\",\"description\":\"It jams.\"}";
        String comment = "{\"body\":\"Any news?\"}";
        String agentUpdate = "{\"status\":\"IN_PROGRESS\",\"priority\":\"HIGH\",\"assigneeId\":null,\"resolution\":null}";
        String agentComment = "{\"body\":\"Checked the logs.\",\"internal\":true}";

        return List.of(
                new Endpoint("list own tickets", HttpMethod.GET, "/api/tickets", null, requesterOnly),
                new Endpoint("file a ticket", HttpMethod.POST, "/api/tickets", ticketBody, with(requesterOnly, CREATED)),
                new Endpoint("view a ticket", HttpMethod.GET, "/api/tickets/{t}", null, requesterObject),
                new Endpoint("comment on a ticket", HttpMethod.POST, "/api/tickets/{t}/comments", comment, requesterObject),
                new Endpoint("upload to a ticket", HttpMethod.POST, "/api/tickets/{t}/attachments", "UPLOAD",
                        with(requesterObject, CREATED)),
                new Endpoint("download an attachment", HttpMethod.GET, "/api/tickets/{t}/attachments/{a}", null, requesterObject),

                new Endpoint("see the queue", HttpMethod.GET, "/api/queue", null, agentOnly),
                new Endpoint("list agents", HttpMethod.GET, "/api/queue/agents", null, agentOnly),
                new Endpoint("view a queue ticket", HttpMethod.GET, "/api/queue/{t}", null, agentOnly),
                new Endpoint("update a queue ticket", HttpMethod.PUT, "/api/queue/{t}", agentUpdate, agentOnly),
                new Endpoint("add an internal note", HttpMethod.POST, "/api/queue/{t}/comments", agentComment, agentOnly),
                new Endpoint("upload as agent", HttpMethod.POST, "/api/queue/{t}/attachments", "UPLOAD", with(agentOnly, CREATED)),
                new Endpoint("download as agent", HttpMethod.GET, "/api/queue/{t}/attachments/{a}", null, agentOnly),

                new Endpoint("list categories", HttpMethod.GET, "/api/categories", null, anyUser),

                new Endpoint("list users", HttpMethod.GET, "/api/admin/users", null, adminOnly),
                new Endpoint("create a user", HttpMethod.POST, "/api/admin/users",
                        "{\"username\":\"u{rnd}\",\"displayName\":\"U\",\"email\":null,\"role\":\"REQUESTER\"}",
                        with(adminOnly, CREATED)),
                new Endpoint("change a role", HttpMethod.PUT, "/api/admin/users/{u}/role", "{\"role\":\"REQUESTER\"}", adminOnly),
                new Endpoint("enable a user", HttpMethod.PUT, "/api/admin/users/{u}/enabled", "{\"enabled\":true}", adminOnly),
                new Endpoint("reset a factor", HttpMethod.POST, "/api/admin/users/{u}/mfa-reset", null, adminOnly),
                new Endpoint("make MFA mandatory", HttpMethod.PUT, "/api/admin/users/{u}/mfa-required", "{\"required\":true}", adminOnly),
                new Endpoint("issue a temporary password", HttpMethod.POST, "/api/admin/users/{u}/temporary-password", null, adminOnly),
                new Endpoint("list all categories", HttpMethod.GET, "/api/admin/categories", null, adminOnly),
                new Endpoint("add a category", HttpMethod.POST, "/api/admin/categories", "{\"name\":\"C{rnd}\"}",
                        with(adminOnly, CREATED)),
                new Endpoint("rename a category", HttpMethod.PUT, "/api/admin/categories/1", "{\"name\":\"Hardware\",\"active\":true}", adminOnly),
                new Endpoint("read retention", HttpMethod.GET, "/api/admin/settings/retention", null, adminOnly),
                new Endpoint("change retention", HttpMethod.PUT, "/api/admin/settings/retention", "{\"months\":24}", adminOnly),
                new Endpoint("run retention", HttpMethod.POST, "/api/admin/settings/retention/run", null, adminOnly),
                new Endpoint("read the audit log", HttpMethod.GET, "/api/admin/audit", null, adminOnly),
                new Endpoint("read the event catalogue", HttpMethod.GET, "/api/admin/audit/types", null, adminOnly),
                new Endpoint("verify the hash chain", HttpMethod.POST, "/api/admin/audit/verify", null, adminOnly));
    }

    private static Map<Who, Integer> with(Map<Who, Integer> base, int success) {
        Map<Who, Integer> copy = new java.util.EnumMap<>(base);
        copy.replaceAll((who, code) -> code == OK ? success : code);
        return copy;
    }

    Stream<Arguments> cases() {
        List<Arguments> cases = new ArrayList<>();
        for (Endpoint endpoint : endpoints()) {
            for (Who who : Who.values()) {
                cases.add(Arguments.of(endpoint.name(), who, endpoint));
            }
        }
        return cases.stream();
    }

    @ParameterizedTest(name = "{1} -> {0}")
    @MethodSource("cases")
    void matrix(String name, Who who, Endpoint endpoint) throws Exception {
        boolean other = who == Who.REQUESTER_OTHER;
        boolean agentSide = endpoint.path().startsWith("/api/queue");
        Ticket ticket = other && !agentSide ? ticketB : ticketA;
        Attachment attachment = ticket == ticketB ? attachmentB : attachmentA;
        String path = endpoint.path()
                .replace("{t}", ticket.getId().toString())
                .replace("{a}", attachment.getId().toString())
                .replace("{u}", target.getId().toString());

        AbstractMockHttpServletRequestBuilder<?> request;
        if ("UPLOAD".equals(endpoint.body())) {
            request = multipart(path).file(new MockMultipartFile("file", "note.txt", "text/plain",
                    "a note".getBytes(StandardCharsets.UTF_8)));
        } else {
            request = request(endpoint.method(), path);
            if (endpoint.body() != null) {
                String body = endpoint.body().replace("{rnd}", UUID.randomUUID().toString().substring(0, 8));
                request.contentType(MediaType.APPLICATION_JSON).content(body);
            }
        }
        AppUser principal = switch (who) {
            case ANONYMOUS -> null;
            case REQUESTER_OWN, REQUESTER_OTHER -> requesterA;
            case AGENT -> agent;
            case ADMIN -> admin;
        };
        request.with(principal == null ? Sessions.anonymous() : Sessions.signedIn(reload(principal), clock.instant()));

        int status = mvc.perform(request).andReturn().getResponse().getStatus();
        assertThat(status).as("%s as %s (%s %s)", name, who, endpoint.method(), path)
                .isEqualTo(endpoint.expected().get(who));
    }

    /** Every mapped API endpoint must appear above; a new one that does not fails here. */
    @org.junit.jupiter.api.Test
    void everyEndpointIsInTheMatrix(@Autowired @org.springframework.beans.factory.annotation.Qualifier("requestMappingHandlerMapping")
                                    org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping mapping) {
        List<String> tested = endpoints().stream().map(e -> e.method() + " " + e.path()
                .replace("{t}", "{id}").replace("{u}", "{id}").replace("{a}", "{attachmentId}")
                .replace("/api/admin/categories/1", "/api/admin/categories/{id}")).toList();
        List<String> mapped = mapping.getHandlerMethods().keySet().stream()
                .flatMap(info -> info.getPatternValues().stream().flatMap(pattern -> info.getMethodsCondition()
                        .getMethods().stream().map(method -> method + " " + pattern)))
                .filter(entry -> entry.contains(" /api/") && !entry.contains(" /api/auth/") && !entry.contains(" /api/account/"))
                .filter(entry -> !entry.equals("DELETE /api/admin/users/{id}"))   // covered in UserAdministrationTest
                .toList();
        assertThat(tested).containsAll(mapped);
    }
}
