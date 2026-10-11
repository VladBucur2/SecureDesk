package nl.fontys.securedesk.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import nl.fontys.securedesk.user.AppUser;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Everything the sign-in does to the HTTP session, in one place. The rules from BoK 6.1:
 * a fresh session at the password step, nothing but a {@link PendingLogin} until the last stage,
 * and a rotated session id plus a new CSRF token at the moment the session becomes authenticated,
 * so a session or token fixated before sign-in cannot survive into the signed-in state.
 */
@Component
public class AuthSessions {

    public static final String PENDING = "securedesk.pending";
    public static final String AUTH_TIME = "securedesk.authTime";
    public static final String LOGIN_TIME = "securedesk.loginTime";

    private final SecurityContextRepository contextRepository;
    private final CsrfTokenRepository csrfTokenRepository;

    public AuthSessions(SecurityContextRepository contextRepository, CsrfTokenRepository csrfTokenRepository) {
        this.contextRepository = contextRepository;
        this.csrfTokenRepository = csrfTokenRepository;
    }

    /** Password accepted: whatever session existed is discarded and a new one holds only the pending state. */
    public PendingLogin startPending(HttpServletRequest request, AppUser user, String throttleKey,
                                     List<AuthStage> stages) {
        HttpSession old = request.getSession(false);
        if (old != null) {
            old.invalidate();
        }
        SecurityContextHolder.clearContext();
        PendingLogin pending = new PendingLogin(user.getId(), throttleKey, stages);
        request.getSession(true).setAttribute(PENDING, pending);
        return pending;
    }

    public Optional<PendingLogin> pending(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return Optional.empty();
        }
        return Optional.ofNullable((PendingLogin) session.getAttribute(PENDING));
    }

    public void save(HttpServletRequest request, PendingLogin pending) {
        request.getSession().setAttribute(PENDING, pending);
    }

    /**
     * Promotes the pending session to an authenticated one. The session id is rotated first,
     * then the principal and its authority are attached, then the CSRF token is replaced.
     */
    public void signIn(HttpServletRequest request, HttpServletResponse response, AppUser user, Instant now) {
        HttpSession session = request.getSession();
        session.removeAttribute(PENDING);
        request.changeSessionId();
        storePrincipal(request, response, user);
        session = request.getSession();
        session.setAttribute(AUTH_TIME, now);
        session.setAttribute(LOGIN_TIME, now);
        csrfTokenRepository.saveToken(null, request, response);
    }

    /** After the user changed their own password: other sessions end, this one carries the new stamp. */
    public void refreshPrincipal(HttpServletRequest request, HttpServletResponse response, AppUser user) {
        request.changeSessionId();
        storePrincipal(request, response, user);
        csrfTokenRepository.saveToken(null, request, response);
    }

    public void markReauthenticated(HttpServletRequest request, Instant now) {
        request.getSession().setAttribute(AUTH_TIME, now);
    }

    public Optional<Instant> authTime(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session == null ? Optional.empty() : Optional.ofNullable((Instant) session.getAttribute(AUTH_TIME));
    }

    public Optional<Instant> loginTime(HttpSession session) {
        return Optional.ofNullable((Instant) session.getAttribute(LOGIN_TIME));
    }

    public void end(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.clearContext();
    }

    private void storePrincipal(HttpServletRequest request, HttpServletResponse response, AppUser user) {
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                SessionUser.of(user), null, List.of(new SimpleGrantedAuthority(user.getRole().authority())));
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        contextRepository.saveContext(context, request, response);
    }
}
