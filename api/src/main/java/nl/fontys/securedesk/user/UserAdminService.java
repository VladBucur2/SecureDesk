package nl.fontys.securedesk.user;

import nl.fontys.securedesk.audit.AuditLog;
import nl.fontys.securedesk.audit.AuditType;
import nl.fontys.securedesk.auth.CurrentUser;
import nl.fontys.securedesk.auth.RecoveryCodeRepository;
import nl.fontys.securedesk.common.ApiException;
import nl.fontys.securedesk.common.TextSanitizer;
import nl.fontys.securedesk.crypto.PasswordHasher;
import nl.fontys.securedesk.crypto.PasswordPolicy;
import nl.fontys.securedesk.ticket.TicketErasure;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

/**
 * UC-05: create accounts, change roles, disable leavers, reset a lost factor. These are exactly
 * the actions an attacker with administrator access takes, so each one is an audit event, most of
 * them with the alert flag, and each one that changes what a session may do rotates the account's
 * security stamp, which ends that account's sessions at their next request.
 *
 * <p>Two guards keep the system administrable: nobody can disable, demote or erase their own
 * account, and the last enabled administrator cannot be removed.
 */
@Service
public class UserAdminService {

    private final AppUserRepository users;
    private final RecoveryCodeRepository recoveryCodes;
    private final PasswordHasher hasher;
    private final PasswordPolicy policy;
    private final TicketErasure ticketErasure;
    private final AuditLog audit;
    private final Clock clock;

    public UserAdminService(AppUserRepository users, RecoveryCodeRepository recoveryCodes, PasswordHasher hasher,
                            PasswordPolicy policy, TicketErasure ticketErasure, AuditLog audit, Clock clock) {
        this.users = users;
        this.recoveryCodes = recoveryCodes;
        this.hasher = hasher;
        this.policy = policy;
        this.ticketErasure = ticketErasure;
        this.audit = audit;
        this.clock = clock;
    }

    public Page<AppUser> list(int page, int size) {
        return users.findAllByOrderByUsernameAsc(PageRequest.of(page, size));
    }

    public record Created(AppUser user, String temporaryPassword) {
    }

    @Transactional
    public Created create(UserDtos.CreateUserRequest request) {
        String username = request.username().toLowerCase(java.util.Locale.ROOT);
        if (users.existsByUsername(username)) {
            throw ApiException.conflict("username_taken", "That username is already in use.");
        }
        Instant now = clock.instant();
        AppUser user = new AppUser(username, TextSanitizer.cleanLine(request.displayName()),
                request.email() == null || request.email().isBlank() ? null : request.email().strip(),
                request.role(), now);
        user.setMfaRequired(request.mfaRequired() == null || request.mfaRequired());
        String temporary = policy.accept(TemporaryPasswords.generate());
        user.setPasswordRecord(hasher.newPasswordRecord(user.getId(), temporary));
        user.setPasswordChangeRequired(true);
        users.save(user);
        audit.event(AuditType.USER_CREATED).target("user", user.getId())
                .detail("username", user.getUsername()).detail("role", user.getRole()).write();
        return new Created(user, temporary);
    }

    @Transactional
    public AppUser changeRole(UUID id, Role role) {
        AppUser user = load(id);
        notSelf(user, "change your own role");
        Role old = user.getRole();
        if (old == role) {
            return user;
        }
        if (old == Role.ADMIN) {
            keepOneAdmin(user);
        }
        user.setRole(role);
        user.rotateSecurityStamp(clock.instant());
        audit.event(AuditType.USER_ROLE_CHANGED).target("user", user.getId())
                .detail("username", user.getUsername()).detail("old_role", old).detail("new_role", role).write();
        return users.save(user);
    }

    @Transactional
    public AppUser setEnabled(UUID id, boolean enabled) {
        AppUser user = load(id);
        notSelf(user, "disable your own account");
        if (user.isErased()) {
            throw ApiException.conflict("erased", "This account has been erased.");
        }
        if (user.isEnabled() == enabled) {
            return user;
        }
        if (!enabled && user.getRole() == Role.ADMIN) {
            keepOneAdmin(user);
        }
        user.setEnabled(enabled);
        user.rotateSecurityStamp(clock.instant());
        audit.event(enabled ? AuditType.USER_ENABLED : AuditType.USER_DISABLED).target("user", user.getId())
                .detail("username", user.getUsername()).write();
        return users.save(user);
    }

    /**
     * Removes the factor and the recovery codes. The account enrols again at its next sign-in if
     * a factor is mandatory for it; every generator holding the old secret becomes useless.
     */
    @Transactional
    public AppUser resetMfa(UUID id) {
        AppUser user = load(id);
        user.removeSecondFactor(clock.instant());
        recoveryCodes.deleteByUserId(user.getId());
        audit.event(AuditType.MFA_RESET).target("user", user.getId()).detail("username", user.getUsername()).write();
        return users.save(user);
    }

    /** SR-01: only a requester's factor can be made optional; for the other roles it is always on. */
    @Transactional
    public AppUser setMfaRequired(UUID id, boolean required) {
        AppUser user = load(id);
        if (user.getRole() != Role.REQUESTER) {
            throw ApiException.badRequest("mfa_always_required",
                    "A second factor is always required for agents and administrators.");
        }
        if (user.isMfaRequired() == required) {
            return user;
        }
        user.setMfaRequired(required);
        user.touch(clock.instant());
        audit.event(AuditType.MFA_REQUIREMENT_CHANGED).target("user", user.getId())
                .detail("username", user.getUsername()).detail("required", required).write();
        return users.save(user);
    }

    @Transactional
    public Created issueTemporaryPassword(UUID id) {
        AppUser user = load(id);
        notSelf(user, "reset your own password here; use your account page");
        if (user.isErased()) {
            throw ApiException.conflict("erased", "This account has been erased.");
        }
        String temporary = policy.accept(TemporaryPasswords.generate());
        user.setPasswordRecord(hasher.newPasswordRecord(user.getId(), temporary));
        user.setPasswordChangeRequired(true);
        user.rotateSecurityStamp(clock.instant());
        audit.event(AuditType.PASSWORD_RESET_BY_ADMIN).target("user", user.getId())
                .detail("username", user.getUsername()).write();
        return new Created(users.save(user), temporary);
    }

    /**
     * SR-10: removes a user's personal data. Their tickets are deleted with comments and
     * attachments; the account row stays, anonymised, so that their comments on other tickets and
     * the audit trail still point at one (anonymous) account.
     */
    @Transactional
    public AppUser erase(UUID id) {
        AppUser user = load(id);
        notSelf(user, "erase your own account");
        if (user.isErased()) {
            return user;
        }
        if (user.getRole() == Role.ADMIN) {
            keepOneAdmin(user);
        }
        String formerUsername = user.getUsername();
        TicketErasure.Result removed = ticketErasure.eraseFor(user.getId());
        recoveryCodes.deleteByUserId(user.getId());
        user.erase(clock.instant());
        audit.event(AuditType.USER_ERASED).target("user", user.getId())
                .detail("username", formerUsername)
                .detail("tickets_deleted", removed.ticketsDeleted())
                .detail("tickets_unassigned", removed.ticketsUnassigned()).write();
        return users.save(user);
    }

    private AppUser load(UUID id) {
        return users.findById(id).orElseThrow(ApiException::notFound);
    }

    private static void notSelf(AppUser user, String action) {
        if (CurrentUser.get().map(current -> current.id().equals(user.getId())).orElse(false)) {
            throw ApiException.conflict("own_account", "You cannot " + action + ".");
        }
    }

    private void keepOneAdmin(AppUser user) {
        if (user.isEnabled() && !user.isErased() && users.countByRoleAndEnabledTrueAndErasedAtIsNull(Role.ADMIN) <= 1) {
            throw ApiException.conflict("last_admin", "This is the last enabled administrator.");
        }
    }
}
