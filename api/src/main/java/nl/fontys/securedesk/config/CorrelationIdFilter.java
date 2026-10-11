package nl.fontys.securedesk.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nl.fontys.securedesk.common.RequestContext;
import org.slf4j.MDC;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Ties every log line and audit event of one request together (BoK 5.2.3 C). Nginx generates
 * the id and also writes it to its access log, so a request can be followed from the proxy into
 * the application. A value that does not look like an id is replaced, never trusted.
 */
public class CorrelationIdFilter extends OncePerRequestFilter {

    static final String HEADER = "X-Request-ID";
    private static final Pattern VALID = Pattern.compile("[A-Za-z0-9-]{8,64}");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String supplied = request.getHeader(HEADER);
        String id = supplied != null && VALID.matcher(supplied).matches() ? supplied : UUID.randomUUID().toString();
        request.setAttribute(RequestContext.CORRELATION_ATTRIBUTE, id);
        response.setHeader(HEADER, id);
        MDC.put(RequestContext.CORRELATION_MDC, id);
        try {
            chain.doFilter(request, response);
        } finally {
            MDC.remove(RequestContext.CORRELATION_MDC);
        }
    }
}
