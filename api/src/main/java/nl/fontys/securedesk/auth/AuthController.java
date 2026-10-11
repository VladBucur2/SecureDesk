package nl.fontys.securedesk.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import nl.fontys.securedesk.audit.AuditLog;
import nl.fontys.securedesk.audit.AuditType;
import nl.fontys.securedesk.audit.Outcome;
import nl.fontys.securedesk.common.ApiException;
import nl.fontys.securedesk.user.AppUser;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The two-step sign-in of BoK 5.2.3 A as a JSON API for the React front end:
 *
 * <pre>
 * POST /api/auth/login     password        -> {"stage": "MFA" | "PASSWORD_CHANGE" | "ENROL" | "AUTHENTICATED"}
 * POST /api/auth/mfa       TOTP or recovery code
 * POST /api/auth/password  new password, when a temporary one was issued
 * GET  /api/auth/enrol     a new secret (and /api/auth/enrol/qr.svg), POST it back with a code
 * </pre>
 *
 * There is no formLogin(): until the last stage succeeds, the session holds a {@link PendingLogin}
 * and no Authentication, so every protected URL still refuses it.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    static final String AUTHENTICATED = "AUTHENTICATED";
    private static final String GENERIC_FAILURE = "Those details are not correct.";

    private final AuthService auth;
    private final AuthSessions sessions;
    private final TotpService totp;
    private final AuditLog audit;
    private final Clock clock;
    private final AuthProperties properties;

    public AuthController(AuthService auth, AuthSessions sessions, TotpService totp, AuditLog audit,
                          Clock clock, AuthProperties properties) {
        this.auth = auth;
        this.sessions = sessions;
        this.totp = totp;
        this.audit = audit;
        this.clock = clock;
        this.properties = properties;
    }

    // ---- where the session stands ------------------------------------------------------------

    @GetMapping("/session")
    @PreAuthorize("permitAll()")
    public AuthDtos.SessionState session(HttpServletRequest request) {
        CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        String token = csrf == null ? null : csrf.getToken();
        Optional<SessionUser> current = CurrentUser.get();
        if (current.isPresent()) {
            AppUser user = auth.findUser(current.get().id()).orElseThrow(ApiException::notFound);
            return new AuthDtos.SessionState(AUTHENTICATED, me(user), null, token);
        }
        Optional<PendingLogin> pending = sessions.pending(request);
        if (pending.isPresent()) {
            String username = auth.findUser(pending.get().userId()).map(AppUser::getUsername).orElse(null);
            return new AuthDtos.SessionState(pending.get().current().name(), null, username, token);
        }
        return new AuthDtos.SessionState("ANONYMOUS", null, null, token);
    }

    // ---- step 1: password ----------------------------------------------------------------------

    @PostMapping("/login")
    @PreAuthorize("permitAll()")
    public AuthDtos.StageResponse login(@Valid @RequestBody AuthDtos.LoginRequest body,
                                        HttpServletRequest request, HttpServletResponse response) {
        Optional<AppUser> verified = auth.checkPassword(body.username(), body.password());
        if (verified.isEmpty()) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "auth_failed", GENERIC_FAILURE);
        }
        AppUser user = verified.get();
        PendingLogin pending = sessions.startPending(request, user,
                LoginThrottleService.keyFor(body.username()), auth.stagesFor(user));
        return advance(pending, user, request, response);
    }

    // ---- step 2: the code ----------------------------------------------------------------------

    @PostMapping("/mfa")
    @PreAuthorize("permitAll()")
    public AuthDtos.StageResponse mfa(@Valid @RequestBody AuthDtos.CodeRequest body,
                                      HttpServletRequest request, HttpServletResponse response) {
        PendingLogin pending = requireStage(request, AuthStage.MFA);
        AppUser user = pendingUser(pending);
        AuthService.CodeResult result = auth.checkCode(user, pending.throttleKey(), body.code(), true);
        switch (result.status()) {
            case OK -> {
                audit.event(AuditType.MFA_VERIFY).actor(user).detail("method", result.method()).write();
                pending.pass(AuthStage.MFA);
                return advance(pending, user, request, response);
            }
            case LOCKED -> {
                sessions.end(request);
                throw new ApiException(HttpStatus.UNAUTHORIZED, "auth_failed", GENERIC_FAILURE);
            }
            default -> {
                audit.event(AuditType.MFA_VERIFY).actor(user).outcome(Outcome.FAILURE)
                        .detail("failed_count", result.failures()).write();
                throw ApiException.badRequest("invalid_code", "That code is not valid.");
            }
        }
    }

    // ---- temporary password --------------------------------------------------------------------

    @PostMapping("/password")
    @PreAuthorize("permitAll()")
    public AuthDtos.StageResponse newPassword(@Valid @RequestBody AuthDtos.NewPasswordRequest body,
                                              HttpServletRequest request, HttpServletResponse response) {
        PendingLogin pending = requireStage(request, AuthStage.PASSWORD_CHANGE);
        AppUser user = auth.setNewPassword(pendingUser(pending), body.newPassword());
        pending.pass(AuthStage.PASSWORD_CHANGE);
        return advance(pending, user, request, response);
    }

    // ---- enrolment -----------------------------------------------------------------------------

    @GetMapping("/enrol")
    @PreAuthorize("permitAll()")
    public ResponseEntity<AuthDtos.Enrolment> enrolment(HttpServletRequest request) {
        PendingLogin pending = requireStage(request, AuthStage.ENROL);
        AppUser user = pendingUser(pending);
        String secret = enrolmentSecret(pending, user, request);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(new AuthDtos.Enrolment(secret, totp.otpAuthUri(user.getUsername(), secret),
                        properties.issuer(), user.getUsername()));
    }

    /** The QR code is rendered from the session, so the secret never travels in a URL. */
    @GetMapping(value = "/enrol/qr.svg", produces = "image/svg+xml")
    @PreAuthorize("permitAll()")
    public ResponseEntity<String> enrolmentQr(HttpServletRequest request) {
        PendingLogin pending = requireStage(request, AuthStage.ENROL);
        AppUser user = pendingUser(pending);
        String secret = enrolmentSecret(pending, user, request);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(QrCodeSvg.render(totp.otpAuthUri(user.getUsername(), secret)));
    }

    @PostMapping("/enrol")
    @PreAuthorize("permitAll()")
    public AuthDtos.EnrolmentDone confirmEnrolment(@Valid @RequestBody AuthDtos.CodeRequest body,
                                                   HttpServletRequest request, HttpServletResponse response) {
        PendingLogin pending = requireStage(request, AuthStage.ENROL);
        AppUser user = pendingUser(pending);
        AuthService.CodeResult result = auth.confirmEnrolment(user, pending.throttleKey(), body.code());
        switch (result.status()) {
            case OK -> {
                List<String> codes = auth.issueRecoveryCodes(user);
                pending.pass(AuthStage.ENROL);
                AuthDtos.StageResponse next = advance(pending, pendingUser(pending), request, response);
                return new AuthDtos.EnrolmentDone(next.stage(), codes);
            }
            case LOCKED -> {
                sessions.end(request);
                throw new ApiException(HttpStatus.UNAUTHORIZED, "auth_failed", GENERIC_FAILURE);
            }
            default -> throw ApiException.badRequest("invalid_code",
                    "That code is not valid; the second factor was not enabled.");
        }
    }

    // ---- step-up and sign-out ------------------------------------------------------------------

    /**
     * Step-up authentication before administrative actions (UC-05): a fresh TOTP code, with the
     * same replay protection and lockout as the sign-in. Recovery codes are not accepted here.
     */
    @PostMapping("/reauth")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> reauthenticate(@Valid @RequestBody AuthDtos.CodeRequest body,
                                               HttpServletRequest request) {
        AppUser user = auth.findUser(CurrentUser.require().id()).orElseThrow(ApiException::notFound);
        if (!user.isMfaEnabled()) {
            throw ApiException.badRequest("no_second_factor", "This account has no second factor to confirm with.");
        }
        AuthService.CodeResult result = auth.checkCode(user, LoginThrottleService.keyFor(user.getUsername()),
                body.code(), false);
        switch (result.status()) {
            case OK -> {
                sessions.markReauthenticated(request, clock.instant());
                audit.event(AuditType.REAUTH).write();
                return ResponseEntity.noContent().build();
            }
            case LOCKED -> {
                audit.event(AuditType.REAUTH).outcome(Outcome.LOCKED).write();
                sessions.end(request);
                throw new ApiException(HttpStatus.UNAUTHORIZED, "auth_failed", GENERIC_FAILURE);
            }
            default -> {
                audit.event(AuditType.REAUTH).outcome(Outcome.FAILURE)
                        .detail("failed_count", result.failures()).write();
                throw ApiException.badRequest("invalid_code", "That code is not valid.");
            }
        }
    }

    /** Also cancels a sign-in that is half-way. */
    @PostMapping("/logout")
    @PreAuthorize("permitAll()")
    public ResponseEntity<Map<String, String>> logout(HttpServletRequest request) {
        if (CurrentUser.get().isPresent()) {
            audit.event(AuditType.LOGOUT).write();
        }
        sessions.end(request);
        return ResponseEntity.ok(Map.of("stage", "ANONYMOUS"));
    }

    // ---- helpers -------------------------------------------------------------------------------

    /** Moves to the next stage, or signs in when there is none. */
    private AuthDtos.StageResponse advance(PendingLogin pending, AppUser user,
                                           HttpServletRequest request, HttpServletResponse response) {
        if (!pending.done()) {
            sessions.save(request, pending);
            return new AuthDtos.StageResponse(pending.current().name());
        }
        AppUser fresh = auth.findUser(user.getId()).orElseThrow(ApiException::notFound);
        sessions.signIn(request, response, fresh, clock.instant());
        auth.completed(pending.throttleKey());
        audit.event(AuditType.LOGIN_COMPLETE).actor(fresh).detail("factors", pending.factors()).write();
        return new AuthDtos.StageResponse(AUTHENTICATED);
    }

    private PendingLogin requireStage(HttpServletRequest request, AuthStage stage) {
        return sessions.pending(request)
                .filter(p -> p.isAt(stage))
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "no_pending_login",
                        "Your sign-in has expired. Please start again."));
    }

    private AppUser pendingUser(PendingLogin pending) {
        return auth.findUser(pending.userId())
                .filter(AppUser::canSignIn)
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "no_pending_login",
                        "Your sign-in has expired. Please start again."));
    }

    private String enrolmentSecret(PendingLogin pending, AppUser user, HttpServletRequest request) {
        if (pending.enrolmentStarted()) {
            Optional<String> existing = auth.enrolmentSecret(user);
            if (existing.isPresent()) {
                return existing.get();
            }
        }
        String secret = auth.beginEnrolment(user);
        pending.markEnrolmentStarted();
        sessions.save(request, pending);
        return secret;
    }

    private AuthDtos.Me me(AppUser user) {
        return new AuthDtos.Me(user.getId(), user.getUsername(), user.getDisplayName(), user.getRole(),
                user.isMfaEnabled(), user.mfaMandatory(), auth.remainingRecoveryCodes(user));
    }
}
