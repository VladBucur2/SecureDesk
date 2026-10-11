package nl.fontys.securedesk.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nl.fontys.securedesk.audit.AuditLog;
import nl.fontys.securedesk.audit.AuditType;
import nl.fontys.securedesk.audit.Outcome;
import nl.fontys.securedesk.common.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.Clock;
import java.time.Instant;

/** Enforces {@link RequiresRecentAuthentication}. */
@Component
public class RecentAuthenticationInterceptor implements HandlerInterceptor {

    private final AuthSessions sessions;
    private final AuditLog audit;
    private final Clock clock;
    private final AuthProperties properties;

    public RecentAuthenticationInterceptor(AuthSessions sessions, AuditLog audit, Clock clock,
                                           AuthProperties properties) {
        this.sessions = sessions;
        this.audit = audit;
        this.clock = clock;
        this.properties = properties;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod method)
                || !method.hasMethodAnnotation(RequiresRecentAuthentication.class)) {
            return true;
        }
        Instant cutoff = clock.instant().minus(properties.recentAuthWindow());
        boolean recent = sessions.authTime(request).map(time -> time.isAfter(cutoff)).orElse(false);
        if (!recent) {
            audit.event(AuditType.REAUTH_REQUIRED).outcome(Outcome.DENIED)
                    .detail("path", request.getRequestURI()).write();
            throw new ApiException(HttpStatus.FORBIDDEN, "reauth_required",
                    "Confirm it is you: enter a code from your authenticator app.");
        }
        return true;
    }
}
