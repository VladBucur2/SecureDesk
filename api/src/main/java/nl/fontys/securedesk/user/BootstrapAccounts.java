package nl.fontys.securedesk.user;

import nl.fontys.securedesk.audit.AuditLog;
import nl.fontys.securedesk.audit.AuditType;
import nl.fontys.securedesk.crypto.PasswordHasher;
import nl.fontys.securedesk.crypto.PasswordPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;

/**
 * The first administrator, and in the laboratory the demonstration accounts.
 *
 * <p>The administrator is created only when there are no accounts at all, with the password from
 * the secret file the setup step generated, and must choose a new password and enrol a second
 * factor at the first sign-in. The demonstration accounts are created only when
 * {@code securedesk.demo.enabled} is true; they share one generated password and must enrol a
 * factor too, except "bob", a requester for whom an administrator made the factor optional, so
 * that one-factor and two-factor sign-in can be shown side by side as in BoK 6.1 case 1.
 * Neither password is ever logged.
 */
@Component
@Order(1)
class BootstrapAccounts implements ApplicationRunner {

    private static final Logger LOG = LoggerFactory.getLogger(BootstrapAccounts.class);

    private record Demo(String username, String displayName, String email, Role role, boolean mfaRequired) {
    }

    private static final Demo[] DEMO_ACCOUNTS = {
            new Demo("alice", "Alice Jansen", "alice@securedesk.localhost", Role.REQUESTER, true),
            new Demo("bob", "Bob de Vries", "bob@securedesk.localhost", Role.REQUESTER, false),
            new Demo("carol", "Carol Bakker", "carol@securedesk.localhost", Role.AGENT, true),
            new Demo("dave", "Dave Smit", "dave@securedesk.localhost", Role.AGENT, true),
    };

    private final AppUserRepository users;
    private final PasswordHasher hasher;
    private final PasswordPolicy policy;
    private final AuditLog audit;
    private final Clock clock;
    private final String adminUsername;
    private final String adminPassword;
    private final boolean demoEnabled;
    private final String demoPassword;

    BootstrapAccounts(AppUserRepository users, PasswordHasher hasher, PasswordPolicy policy, AuditLog audit,
                      Clock clock,
                      @Value("${securedesk.bootstrap.admin-username:admin}") String adminUsername,
                      @Value("${securedesk.bootstrap.admin-password:}") String adminPassword,
                      @Value("${securedesk.demo.enabled:false}") boolean demoEnabled,
                      @Value("${securedesk.demo.password:}") String demoPassword) {
        this.users = users;
        this.hasher = hasher;
        this.policy = policy;
        this.audit = audit;
        this.clock = clock;
        this.adminUsername = adminUsername;
        this.adminPassword = adminPassword.strip();
        this.demoEnabled = demoEnabled;
        this.demoPassword = demoPassword.strip();
    }

    @Override
    public void run(ApplicationArguments args) {
        if (users.count() == 0) {
            if (adminPassword.isEmpty()) {
                LOG.warn("no accounts exist and no bootstrap administrator password is configured");
            } else {
                create(adminUsername, "Administrator", null, Role.ADMIN, true, adminPassword, true, "bootstrap");
            }
        }
        if (demoEnabled && !demoPassword.isEmpty()) {
            for (Demo demo : DEMO_ACCOUNTS) {
                if (!users.existsByUsername(demo.username())) {
                    create(demo.username(), demo.displayName(), demo.email(), demo.role(), demo.mfaRequired(),
                            demoPassword, false, "demo");
                }
            }
        }
    }

    private void create(String username, String displayName, String email, Role role, boolean mfaRequired,
                        String password, boolean mustChange, String origin) {
        String accepted;
        try {
            accepted = policy.accept(password, username, displayName);
        } catch (PasswordPolicy.Rejected rejected) {
            LOG.error("{} account '{}' not created: the configured password is refused ({})",
                    origin, username, rejected.getMessage());
            return;
        }
        Instant now = clock.instant();
        AppUser user = new AppUser(username, displayName, email, role, now);
        user.setMfaRequired(mfaRequired);
        user.setPasswordRecord(hasher.newPasswordRecord(user.getId(), accepted));
        user.setPasswordChangeRequired(mustChange);
        users.save(user);
        audit.event(AuditType.USER_CREATED).system().target("user", user.getId())
                .detail("username", username).detail("role", role).detail("origin", origin).write();
        LOG.info("{} account '{}' created with role {}", origin, username, role);
    }
}
