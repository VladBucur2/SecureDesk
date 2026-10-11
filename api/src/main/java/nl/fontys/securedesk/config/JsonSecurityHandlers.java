package nl.fontys.securedesk.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nl.fontys.securedesk.audit.AuditLog;
import nl.fontys.securedesk.audit.AuditType;
import nl.fontys.securedesk.audit.Outcome;
import nl.fontys.securedesk.common.RequestContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * JSON answers for 401 and 403, written here because these requests never reach a controller.
 * Every 403 is an audit event (OWASP: authorisation failures); a burst of them in one session is
 * one of the detection rules handed to the blue team.
 */
@Component
public class JsonSecurityHandlers implements AuthenticationEntryPoint, AccessDeniedHandler {

    private final AuditLog audit;

    public JsonSecurityHandlers(AuditLog audit) {
        this.audit = audit;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         org.springframework.security.core.AuthenticationException exception) throws IOException {
        write(response, HttpStatus.UNAUTHORIZED, "unauthenticated", "Please sign in.");
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception)
            throws IOException {
        if (exception instanceof CsrfException) {
            audit.event(AuditType.CSRF_DENIED).outcome(Outcome.DENIED)
                    .detail("reason", "csrf").detail("method", request.getMethod())
                    .detail("path", request.getRequestURI()).write();
            write(response, HttpStatus.FORBIDDEN, "csrf", "Your session has changed. Reload the page and try again.");
            return;
        }
        audit.event(AuditType.AUTHZ_DENIED).outcome(Outcome.DENIED)
                .detail("reason", "authorization").detail("method", request.getMethod())
                .detail("path", request.getRequestURI()).write();
        write(response, HttpStatus.FORBIDDEN, "forbidden", "You do not have access to this.");
    }

    /** Constant messages and a correlation id of [A-Za-z0-9-] only, so concatenation is safe. */
    private static void write(HttpServletResponse response, HttpStatus status, String code, String message)
            throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write("{\"error\":\"" + code + "\",\"message\":\"" + message
                + "\",\"correlationId\":\"" + RequestContext.correlationId() + "\"}");
    }
}
