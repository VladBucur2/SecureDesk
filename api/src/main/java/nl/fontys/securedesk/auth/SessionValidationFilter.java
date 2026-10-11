package nl.fontys.securedesk.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import nl.fontys.securedesk.audit.AuditLog;
import nl.fontys.securedesk.audit.AuditType;
import nl.fontys.securedesk.user.AppUser;
import nl.fontys.securedesk.user.AppUserRepository;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.Optional;

/**
 * Checks on every request that an authenticated session still matches its account. A role
 * change, a disable, an MFA reset, a password change or an erasure gives the account a new
 * security stamp, and every session carrying the old one ends here, at its next request. That is
 * what makes a leaver's access stop at once and a demoted administrator lose the role at once,
 * rather than at the end of the session (SC-01: session rotation on privilege change).
 *
 * <p>It also enforces the absolute session lifetime; the idle timeout is the servlet container's.
 */
public class SessionValidationFilter extends OncePerRequestFilter {

    private final AppUserRepository users;
    private final AuthSessions sessions;
    private final AuditLog audit;
    private final Clock clock;
    private final Duration absoluteLifetime;

    public SessionValidationFilter(AppUserRepository users, AuthSessions sessions, AuditLog audit, Clock clock,
                                   Duration absoluteLifetime) {
        this.users = users;
        this.sessions = sessions;
        this.audit = audit;
        this.clock = clock;
        this.absoluteLifetime = absoluteLifetime;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Optional<SessionUser> principal = CurrentUser.get();
        HttpSession session = request.getSession(false);
        if (principal.isPresent() && session != null) {
            SessionUser current = principal.get();
            Optional<AppUser> account = users.findById(current.id());
            if (account.isEmpty() || !stillValid(account.get(), current)) {
                audit.event(AuditType.SESSION_REVOKED).detail("reason", "account_changed").write();
                sessions.end(request);
            } else if (sessions.loginTime(session)
                    .map(start -> start.plus(absoluteLifetime).isBefore(clock.instant()))
                    .orElse(true)) {
                audit.event(AuditType.SESSION_EXPIRED).detail("reason", "absolute_lifetime").write();
                sessions.end(request);
            }
        } else if (principal.isPresent()) {
            SecurityContextHolder.clearContext();
        }
        chain.doFilter(request, response);
    }

    private static boolean stillValid(AppUser account, SessionUser session) {
        return account.isEnabled()
                && !account.isErased()
                && account.getRole() == session.role()
                && account.getSecurityStamp().equals(session.stamp());
    }
}
