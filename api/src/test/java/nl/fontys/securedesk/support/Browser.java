package nl.fontys.securedesk.support;

import com.jayway.jsonpath.JsonPath;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.nio.charset.StandardCharsets;

/**
 * Behaves like the React front end: keeps the session it was given (following rotation and
 * invalidation), fetches the CSRF token from /api/auth/session and sends it as X-XSRF-TOKEN.
 */
public class Browser {

    private final MockMvc mvc;
    private MockHttpSession session;
    private String csrf;

    public Browser(MockMvc mvc) {
        this.mvc = mvc;
    }

    public MvcResult send(MockHttpServletRequestBuilder request) throws Exception {
        if (session != null) {
            request.session(session);
        }
        if (csrf != null) {
            request.header("X-XSRF-TOKEN", csrf);
        }
        MvcResult result = mvc.perform(request).andReturn();
        HttpSession after = result.getRequest().getSession(false);
        session = after instanceof MockHttpSession mock && !mock.isInvalid() ? mock : null;
        return result;
    }

    /** What the SPA does after every stage change: ask where the session stands, keep the token. */
    public String refresh() throws Exception {
        csrf = null;
        MvcResult result = send(MockMvcRequestBuilders.get("/api/auth/session"));
        String body = body(result);
        csrf = JsonPath.read(body, "$.csrfToken");
        return JsonPath.read(body, "$.stage");
    }

    public MvcResult postJson(String path, String json) throws Exception {
        refresh();
        return send(MockMvcRequestBuilders.post(path).contentType(MediaType.APPLICATION_JSON).content(json));
    }

    public MvcResult putJson(String path, String json) throws Exception {
        refresh();
        return send(MockMvcRequestBuilders.put(path).contentType(MediaType.APPLICATION_JSON).content(json));
    }

    public MvcResult delete(String path) throws Exception {
        refresh();
        return send(MockMvcRequestBuilders.delete(path));
    }

    /** A POST with the token the browser already holds, without refreshing it first. */
    public MvcResult postJsonWithCurrentToken(String path, String json) throws Exception {
        return send(MockMvcRequestBuilders.post(path).contentType(MediaType.APPLICATION_JSON).content(json));
    }

    public MvcResult get(String path) throws Exception {
        return send(MockMvcRequestBuilders.get(path));
    }

    public MockHttpSession session() {
        return session;
    }

    public String sessionId() {
        return session == null ? null : session.getId();
    }

    public static String body(MvcResult result) {
        return new String(result.getResponse().getContentAsByteArray(), StandardCharsets.UTF_8);
    }
}
