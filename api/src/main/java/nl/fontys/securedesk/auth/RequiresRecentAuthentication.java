package nl.fontys.securedesk.auth;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * UC-05: administrative endpoints require the administrator role plus a recent authentication.
 * A method with this annotation is refused with 403 {@code reauth_required} unless the session
 * signed in or stepped up within {@code securedesk.auth.recent-auth-window}. A stolen session
 * cookie is then not enough to change roles or reset someone's factor; the thief also needs a
 * live code. An ArchUnit rule requires it on every state-changing administrative endpoint.
 */
@Documented
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiresRecentAuthentication {
}
