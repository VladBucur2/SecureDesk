package nl.fontys.securedesk.common;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.MDC;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Optional;

/** Where the current request came from, for the audit trail. Outside a request every value is "-". */
public final class RequestContext {

    public static final String CORRELATION_ATTRIBUTE = "securedesk.correlationId";
    public static final String CORRELATION_MDC = "correlation_id";

    private RequestContext() {
    }

    public static Optional<HttpServletRequest> currentRequest() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes instanceof ServletRequestAttributes servlet) {
            return Optional.of(servlet.getRequest());
        }
        return Optional.empty();
    }

    /** The client address. Behind Nginx this is the address Nginx saw (X-Forwarded-For, set by Nginx only). */
    public static String sourceIp() {
        return currentRequest().map(HttpServletRequest::getRemoteAddr).orElse("-");
    }

    /**
     * The first six bytes of a SHA-256 of the session id, as in the mfa-poc: enough to correlate
     * the events of one session, useless to anyone who wants to take it over.
     */
    public static String sessionHash() {
        return currentRequest()
                .map(request -> request.getSession(false))
                .map(HttpSession::getId)
                .map(RequestContext::hashSessionId)
                .orElse("-");
    }

    public static String hashSessionId(String sessionId) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(sessionId.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, 6);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String correlationId() {
        Optional<String> fromRequest = currentRequest()
                .map(request -> request.getAttribute(CORRELATION_ATTRIBUTE))
                .map(Object::toString);
        if (fromRequest.isPresent()) {
            return fromRequest.get();
        }
        String fromMdc = MDC.get(CORRELATION_MDC);
        return fromMdc == null ? "-" : fromMdc;
    }
}
