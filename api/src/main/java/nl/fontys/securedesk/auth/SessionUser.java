package nl.fontys.securedesk.auth;

import nl.fontys.securedesk.user.AppUser;
import nl.fontys.securedesk.user.Role;

import java.io.Serializable;
import java.util.UUID;

/**
 * The principal of a fully authenticated session. It exists only after every stage of the
 * sign-in has succeeded; a session that has passed the password alone carries none (BoK 6.1).
 *
 * @param stamp the account's security stamp at sign-in; a session whose stamp no longer matches
 *              the account is ended by {@link SessionValidationFilter}
 */
public record SessionUser(UUID id, String username, Role role, String stamp) implements Serializable {

    public static SessionUser of(AppUser user) {
        return new SessionUser(user.getId(), user.getUsername(), user.getRole(), user.getSecurityStamp());
    }
}
