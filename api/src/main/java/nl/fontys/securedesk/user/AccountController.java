package nl.fontys.securedesk.user;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import nl.fontys.securedesk.audit.AuditLog;
import nl.fontys.securedesk.audit.AuditType;
import nl.fontys.securedesk.audit.Outcome;
import nl.fontys.securedesk.auth.AuthService;
import nl.fontys.securedesk.auth.AuthSessions;
import nl.fontys.securedesk.auth.CurrentUser;
import nl.fontys.securedesk.auth.RequiresRecentAuthentication;
import nl.fontys.securedesk.common.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** The signed-in user's own account: password change and new recovery codes. */
@RestController
@RequestMapping("/api/account")
public class AccountController {

    private final AuthService auth;
    private final AuthSessions sessions;
    private final AuditLog audit;

    public AccountController(AuthService auth, AuthSessions sessions, AuditLog audit) {
        this.auth = auth;
        this.sessions = sessions;
        this.audit = audit;
    }

    /**
     * Changing a password needs the current one, checked like a sign-in. Afterwards every other
     * session of the account ends; this one continues under a new session id.
     */
    @PostMapping("/password")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> changePassword(@Valid @RequestBody UserDtos.ChangePasswordRequest body,
                                               HttpServletRequest request, HttpServletResponse response) {
        AppUser user = auth.findUser(CurrentUser.require().id()).orElseThrow(ApiException::notFound);
        switch (auth.verifyCurrentPassword(user, body.currentPassword())) {
            case LOCKED -> {
                sessions.end(request);
                throw new ApiException(HttpStatus.UNAUTHORIZED, "auth_failed", "Those details are not correct.");
            }
            case INVALID -> {
                audit.event(AuditType.PASSWORD_CHANGED).outcome(Outcome.FAILURE).detail("reason", "bad_current").write();
                throw ApiException.badRequest("bad_current_password", "Your current password is not correct.");
            }
            default -> {
                AppUser updated = auth.setNewPassword(user, body.newPassword());
                sessions.refreshPrincipal(request, response, updated);
                return ResponseEntity.noContent().build();
            }
        }
    }

    /** Replaces the recovery codes, for instance after several have been used. Needs a fresh code. */
    @PostMapping("/recovery-codes")
    @PreAuthorize("isAuthenticated()")
    @RequiresRecentAuthentication
    public UserDtos.RecoveryCodesView newRecoveryCodes() {
        AppUser user = auth.findUser(CurrentUser.require().id()).orElseThrow(ApiException::notFound);
        if (!user.isMfaEnabled()) {
            throw ApiException.badRequest("no_second_factor", "This account has no second factor.");
        }
        return new UserDtos.RecoveryCodesView(auth.issueRecoveryCodes(user));
    }
}
