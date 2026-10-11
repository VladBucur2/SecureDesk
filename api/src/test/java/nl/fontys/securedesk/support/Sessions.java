package nl.fontys.securedesk.support;

import nl.fontys.securedesk.auth.AuthSessions;
import nl.fontys.securedesk.auth.SessionUser;
import nl.fontys.securedesk.user.AppUser;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * A session exactly as {@link AuthSessions#signIn} leaves it, for tests that are about what a
 * signed-in user may do rather than about signing in. The CSRF token is placed where the real
 * repository keeps it; spring-security-test's csrf() is not used, because it replaces the
 * filter's repository for the rest of the test run.
 */
public final class Sessions {

    private static final String CSRF_ATTRIBUTE = HttpSessionCsrfTokenRepository.class.getName() + ".CSRF_TOKEN";

    private Sessions() {
    }

    public static RequestPostProcessor signedIn(AppUser user, Instant now) {
        MockHttpSession session = new MockHttpSession();
        UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken.authenticated(
                SessionUser.of(user), null, List.of(new SimpleGrantedAuthority(user.getRole().authority())));
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                new SecurityContextImpl(authentication));
        session.setAttribute(AuthSessions.AUTH_TIME, now);
        session.setAttribute(AuthSessions.LOGIN_TIME, now);
        return withCsrf(session);
    }

    /** An anonymous session that holds a valid CSRF token, so a test sees the authorisation answer, not the CSRF one. */
    public static RequestPostProcessor anonymous() {
        return withCsrf(new MockHttpSession());
    }

    private static RequestPostProcessor withCsrf(MockHttpSession session) {
        String token = UUID.randomUUID().toString();
        session.setAttribute(CSRF_ATTRIBUTE, new DefaultCsrfToken("X-XSRF-TOKEN", "_csrf", token));
        return request -> {
            request.setSession(session);
            request.addHeader("X-XSRF-TOKEN", token);
            return request;
        };
    }
}
