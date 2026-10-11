package nl.fontys.securedesk.auth;

import nl.fontys.securedesk.audit.AuditLog;
import nl.fontys.securedesk.audit.AuditType;
import nl.fontys.securedesk.audit.Outcome;
import nl.fontys.securedesk.common.ApiException;
import nl.fontys.securedesk.crypto.PasswordHasher;
import nl.fontys.securedesk.crypto.PasswordPolicy;
import nl.fontys.securedesk.crypto.TotpSecretCipher;
import nl.fontys.securedesk.user.AppUser;
import nl.fontys.securedesk.user.AppUserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * All authentication decisions live here; the controller only translates them to HTTP and
 * moves the session along (as in the mfa-poc).
 *
 * <p>Which failures count: a wrong password, a wrong code, a wrong enrolment code and a wrong
 * step-up code all count towards the lock of the username. A correct password does not clear the
 * count; only a completed sign-in does. Otherwise someone who knows the password could guess
 * codes for ever, nine at a time, logging in again before each tenth.
 */
@Service
public class AuthService {

    public enum CodeStatus { OK, INVALID, LOCKED }

    /** The result of a code: a TOTP code or a recovery code, wrong, or the username is now locked. */
    public record CodeResult(CodeStatus status, String method, int failures) {
        static CodeResult ok(String method) {
            return new CodeResult(CodeStatus.OK, method, 0);
        }
    }

    private static final int RECOVERY_CODE_COUNT = 10;
    private static final Pattern RECOVERY_CODE = Pattern.compile("[A-Z2-7]{8}");

    private final AppUserRepository users;
    private final RecoveryCodeRepository recoveryCodes;
    private final PasswordHasher hasher;
    private final PasswordPolicy policy;
    private final TotpService totp;
    private final TotpSecretCipher totpCipher;
    private final LoginThrottleService throttle;
    private final Sleeper sleeper;
    private final AuditLog audit;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    public AuthService(AppUserRepository users, RecoveryCodeRepository recoveryCodes, PasswordHasher hasher,
                       PasswordPolicy policy, TotpService totp, TotpSecretCipher totpCipher,
                       LoginThrottleService throttle, Sleeper sleeper, AuditLog audit, Clock clock) {
        this.users = users;
        this.recoveryCodes = recoveryCodes;
        this.hasher = hasher;
        this.policy = policy;
        this.totp = totp;
        this.totpCipher = totpCipher;
        this.throttle = throttle;
        this.sleeper = sleeper;
        this.audit = audit;
        this.clock = clock;
    }

    // ---- step 1: the password ------------------------------------------------------------------

    /**
     * Verifies a username and password. Every failure looks the same from outside: the same
     * answer, and for an unknown username a dummy hash so that it also takes the same time.
     */
    public Optional<AppUser> checkPassword(String username, String password) {
        String key = LoginThrottleService.keyFor(username);
        String normalised = LoginThrottleService.normalise(username);
        Optional<AppUser> found = normalised.length() <= 64 ? users.findByUsername(normalised) : Optional.empty();

        LoginThrottleService.State state = throttle.state(key);
        if (state.locked()) {
            hasher.verifyAgainstDummy(password);
            AuditLog.Entry blocked = audit.event(AuditType.LOGIN_BLOCKED).outcome(Outcome.LOCKED);
            found.ifPresentOrElse(blocked::actor, blocked::anonymous);
            blocked.write();
            return Optional.empty();
        }
        sleeper.sleep(state.delay());

        if (found.isEmpty()) {
            hasher.verifyAgainstDummy(password);
            return refusePassword(key, null, "unknown_account");
        }
        AppUser user = found.get();
        PasswordHasher.Check check = hasher.verifyPassword(user.getId(), user.getPasswordRecord(), password);
        if (check.outcome() == PasswordHasher.Outcome.TAMPERED) {
            audit.event(AuditType.CREDENTIAL_TAMPERED).actor(user).outcome(Outcome.FAILURE)
                    .target("user", user.getId()).detail("record", "password").write();
            return refusePassword(key, user, "tampered");
        }
        if (!check.matched()) {
            return refusePassword(key, user, user.getPasswordRecord() == null ? "no_password" : "bad_password");
        }
        if (!user.isEnabled() || user.isErased()) {
            audit.event(AuditType.LOGIN_PASSWORD).actor(user).outcome(Outcome.FAILURE)
                    .detail("reason", "disabled").write();
            return Optional.empty();
        }
        if (check.outcome() == PasswordHasher.Outcome.OK_REHASHED) {
            user.setPasswordRecord(check.upgradedRecord());
            user.touch(clock.instant());
            user = users.save(user);
            audit.event(AuditType.PASSWORD_REHASHED).actor(user).target("user", user.getId()).write();
        }
        audit.event(AuditType.LOGIN_PASSWORD).actor(user).write();
        return Optional.of(user);
    }

    private Optional<AppUser> refusePassword(String key, AppUser user, String reason) {
        LoginThrottleService.State after = throttle.recordFailure(key);
        AuditLog.Entry failure = audit.event(AuditType.LOGIN_PASSWORD).outcome(Outcome.FAILURE)
                .detail("reason", reason).detail("failed_count", after.failures());
        if (user != null) {
            failure.actor(user);
            if (after.locked()) {
                audit.event(AuditType.ACCOUNT_LOCKED).actor(user).outcome(Outcome.LOCKED)
                        .target("user", user.getId()).write();
            }
        } else {
            failure.anonymous();
        }
        failure.write();
        return Optional.empty();
    }

    /** The stages after the password, in the order of {@link AuthStage}. */
    public List<AuthStage> stagesFor(AppUser user) {
        List<AuthStage> stages = new ArrayList<>();
        if (user.isMfaEnabled()) {
            stages.add(AuthStage.MFA);
        }
        if (user.isPasswordChangeRequired()) {
            stages.add(AuthStage.PASSWORD_CHANGE);
        }
        if (!user.isMfaEnabled() && user.mfaMandatory()) {
            stages.add(AuthStage.ENROL);
        }
        return stages;
    }

    // ---- step 2: the code ----------------------------------------------------------------------

    /**
     * Checks a TOTP code, or, when allowed, a recovery code. A TOTP step is accepted once: the
     * update that records it only succeeds when the step is newer than the last accepted one.
     */
    public CodeResult checkCode(AppUser pendingUser, String throttleKey, String input, boolean allowRecovery) {
        LoginThrottleService.State state = throttle.state(throttleKey);
        if (state.locked()) {
            audit.event(AuditType.LOGIN_BLOCKED).actor(pendingUser).outcome(Outcome.LOCKED).write();
            return new CodeResult(CodeStatus.LOCKED, null, 0);
        }
        sleeper.sleep(state.delay());

        AppUser user = users.findById(pendingUser.getId()).orElseThrow(ApiException::notFound);
        Instant now = clock.instant();
        String candidate = input == null ? "" : input.strip();

        if (TotpService.looksLikeCode(candidate) && user.getTotpSecret() != null) {
            Optional<String> secret = openSecret(user);
            if (secret.isPresent()) {
                long step = totp.verify(secret.get(), candidate, now, user.getLastAcceptedStep());
                if (step >= 0 && users.acceptTotpStep(user.getId(), step) == 1) {
                    return CodeResult.ok("totp");
                }
            }
        } else if (allowRecovery) {
            String normalised = candidate.replace("-", "").replace(" ", "").toUpperCase(Locale.ROOT);
            if (RECOVERY_CODE.matcher(normalised).matches() && spendRecoveryCode(user, normalised, now)) {
                audit.event(AuditType.MFA_RECOVERY_USED).actor(user).target("user", user.getId())
                        .detail("remaining", recoveryCodes.countByUserIdAndUsedAtIsNull(user.getId())).write();
                return CodeResult.ok("recovery_code");
            }
        }
        LoginThrottleService.State after = throttle.recordFailure(throttleKey);
        if (after.locked()) {
            audit.event(AuditType.ACCOUNT_LOCKED).actor(user).outcome(Outcome.LOCKED)
                    .target("user", user.getId()).write();
            return new CodeResult(CodeStatus.LOCKED, null, after.failures());
        }
        return new CodeResult(CodeStatus.INVALID, null, after.failures());
    }

    private boolean spendRecoveryCode(AppUser user, String normalised, Instant now) {
        for (RecoveryCode code : recoveryCodes.findByUserIdAndUsedAtIsNull(user.getId())) {
            PasswordHasher.Outcome outcome = hasher.verifyRecoveryCode(code.getId(), code.getCodeRecord(), normalised);
            if (outcome == PasswordHasher.Outcome.TAMPERED) {
                audit.event(AuditType.CREDENTIAL_TAMPERED).actor(user).outcome(Outcome.FAILURE)
                        .target("recovery_code", code.getId()).detail("record", "recovery_code").write();
            } else if (outcome == PasswordHasher.Outcome.OK) {
                return recoveryCodes.markUsed(code.getId(), now) == 1;
            }
        }
        return false;
    }

    private Optional<String> openSecret(AppUser user) {
        try {
            return Optional.of(totpCipher.open(user.getId(), user.getTotpSecret()));
        } catch (GeneralSecurityException e) {
            audit.event(AuditType.CREDENTIAL_TAMPERED).actor(user).outcome(Outcome.FAILURE)
                    .target("user", user.getId()).detail("record", "totp").write();
            return Optional.empty();
        }
    }

    // ---- enrolment -----------------------------------------------------------------------------

    /** Generates and stores a new secret; the factor stays off until a code from it is confirmed. */
    @Transactional
    public String beginEnrolment(AppUser pendingUser) {
        AppUser user = users.findById(pendingUser.getId()).orElseThrow(ApiException::notFound);
        String secret = totp.newSecretBase32();
        user.startEnrolment(totpCipher.seal(user.getId(), secret), clock.instant());
        users.save(user);
        audit.event(AuditType.MFA_ENROL_START).actor(user).target("user", user.getId()).write();
        return secret;
    }

    /** The secret of an enrolment in progress, when the enrolment page is shown again. */
    public Optional<String> enrolmentSecret(AppUser pendingUser) {
        AppUser user = users.findById(pendingUser.getId()).orElseThrow(ApiException::notFound);
        if (user.isMfaEnabled() || user.getTotpSecret() == null) {
            return Optional.empty();
        }
        return openSecret(user);
    }

    /**
     * Confirms enrolment with a live code, which proves the generator and the server agree before
     * the account depends on them, then issues the recovery codes exactly once.
     */
    public CodeResult confirmEnrolment(AppUser pendingUser, String throttleKey, String code) {
        LoginThrottleService.State state = throttle.state(throttleKey);
        if (state.locked()) {
            audit.event(AuditType.LOGIN_BLOCKED).actor(pendingUser).outcome(Outcome.LOCKED).write();
            return new CodeResult(CodeStatus.LOCKED, null, 0);
        }
        sleeper.sleep(state.delay());

        Optional<String> secret = enrolmentSecret(pendingUser);
        Instant now = clock.instant();
        long step = secret.map(s -> totp.verify(s, code == null ? "" : code.strip(), now, -1)).orElse(-1L);
        if (step >= 0) {
            AppUser user = users.findById(pendingUser.getId()).orElseThrow(ApiException::notFound);
            user.confirmEnrolment(step, now);
            users.save(user);
            audit.event(AuditType.MFA_ENROL_CONFIRM).actor(user).target("user", user.getId()).write();
            return CodeResult.ok("totp");
        }
        LoginThrottleService.State after = throttle.recordFailure(throttleKey);
        audit.event(AuditType.MFA_ENROL_CONFIRM).actor(pendingUser).outcome(Outcome.FAILURE)
                .target("user", pendingUser.getId()).detail("failed_count", after.failures()).write();
        if (after.locked()) {
            audit.event(AuditType.ACCOUNT_LOCKED).actor(pendingUser).outcome(Outcome.LOCKED)
                    .target("user", pendingUser.getId()).write();
            return new CodeResult(CodeStatus.LOCKED, null, after.failures());
        }
        return new CodeResult(CodeStatus.INVALID, null, after.failures());
    }

    /** Ten new codes, replacing any old ones; only their sealed hashes are stored. */
    public List<String> issueRecoveryCodes(AppUser user) {
        recoveryCodes.deleteByUserId(user.getId());
        Instant now = clock.instant();
        List<String> plain = new ArrayList<>();
        List<RecoveryCode> rows = new ArrayList<>();
        for (int i = 0; i < RECOVERY_CODE_COUNT; i++) {
            byte[] raw = new byte[5];
            random.nextBytes(raw);
            String value = Base32.encode(raw);                  // 8 characters, 40 bits
            RecoveryCode row = new RecoveryCode(user.getId(), now);
            row.setCodeRecord(hasher.newRecoveryCodeRecord(row.getId(), value));
            rows.add(row);
            plain.add(value.substring(0, 4) + "-" + value.substring(4));
        }
        recoveryCodes.saveAll(rows);
        audit.event(AuditType.RECOVERY_CODES_ISSUED).actor(user).target("user", user.getId())
                .detail("count", RECOVERY_CODE_COUNT).write();
        return plain;
    }

    // ---- passwords -----------------------------------------------------------------------------

    /**
     * Sets a new password: the policy of BoK 6.3, a different value than the current one, a new
     * salted and peppered record, and a new security stamp that ends every other session.
     */
    public AppUser setNewPassword(AppUser target, String newPassword) {
        AppUser user = users.findById(target.getId()).orElseThrow(ApiException::notFound);
        String accepted;
        try {
            accepted = policy.accept(newPassword == null ? "" : newPassword, user.getUsername(), user.getDisplayName());
        } catch (PasswordPolicy.Rejected rejected) {
            audit.event(AuditType.PASSWORD_REJECTED).actor(user).outcome(Outcome.FAILURE)
                    .detail("reason", rejected.getMessage()).write();
            throw ApiException.badRequest("password_rejected", "That password cannot be used: " + rejected.getMessage() + ".");
        }
        if (user.getPasswordRecord() != null
                && hasher.verifyPassword(user.getId(), user.getPasswordRecord(), accepted).matched()) {
            audit.event(AuditType.PASSWORD_REJECTED).actor(user).outcome(Outcome.FAILURE)
                    .detail("reason", "same as current").write();
            throw ApiException.badRequest("password_rejected", "Choose a password different from the current one.");
        }
        Instant now = clock.instant();
        user.setPasswordRecord(hasher.newPasswordRecord(user.getId(), accepted));
        user.setPasswordChangeRequired(false);
        user.rotateSecurityStamp(now);
        AppUser saved = users.save(user);
        audit.event(AuditType.PASSWORD_CHANGED).actor(saved).target("user", saved.getId()).write();
        return saved;
    }

    /**
     * The user's own password change while signed in: the current password is checked like a
     * sign-in, and a wrong one counts towards the lock.
     */
    public CodeStatus verifyCurrentPassword(AppUser user, String currentPassword) {
        String key = LoginThrottleService.keyFor(user.getUsername());
        LoginThrottleService.State state = throttle.state(key);
        if (state.locked()) {
            return CodeStatus.LOCKED;
        }
        sleeper.sleep(state.delay());
        PasswordHasher.Check check = hasher.verifyPassword(user.getId(), user.getPasswordRecord(), currentPassword);
        if (check.matched()) {
            return CodeStatus.OK;
        }
        if (check.outcome() == PasswordHasher.Outcome.TAMPERED) {
            audit.event(AuditType.CREDENTIAL_TAMPERED).actor(user).outcome(Outcome.FAILURE)
                    .target("user", user.getId()).detail("record", "password").write();
        }
        LoginThrottleService.State after = throttle.recordFailure(key);
        if (after.locked()) {
            audit.event(AuditType.ACCOUNT_LOCKED).actor(user).outcome(Outcome.LOCKED)
                    .target("user", user.getId()).write();
            return CodeStatus.LOCKED;
        }
        return CodeStatus.INVALID;
    }

    public void completed(String throttleKey) {
        throttle.recordSuccess(throttleKey);
    }

    public Optional<AppUser> findUser(UUID id) {
        return users.findById(id);
    }

    public long remainingRecoveryCodes(AppUser user) {
        return recoveryCodes.countByUserIdAndUsedAtIsNull(user.getId());
    }
}
