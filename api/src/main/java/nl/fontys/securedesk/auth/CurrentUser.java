package nl.fontys.securedesk.auth;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

/**
 * The authenticated principal, always taken from the security context, never from a request
 * parameter, a header or the body (SC-03).
 */
public final class CurrentUser {

    private CurrentUser() {
    }

    public static Optional<SessionUser> get() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()
                && authentication.getPrincipal() instanceof SessionUser user) {
            return Optional.of(user);
        }
        return Optional.empty();
    }

    public static SessionUser require() {
        return get().orElseThrow(() -> new AuthenticationCredentialsNotFoundException("not signed in"));
    }
}
