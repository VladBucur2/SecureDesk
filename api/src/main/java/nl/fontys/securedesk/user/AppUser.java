package nl.fontys.securedesk.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import nl.fontys.securedesk.common.BaseEntity;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.HexFormat;

/**
 * An account. The record is deliberately minimal (SC-11): a username, a display name, a work
 * email for notifications and a role. Credentials are only ever held in sealed form.
 */
@Entity
@Table(name = "app_user")
public class AppUser extends BaseEntity {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Column(nullable = false, length = 64)
    private String username;

    @Column(name = "display_name", nullable = false, length = 100)
    private String displayName;

    @Column(length = 254)
    private String email;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(nullable = false, length = 16)
    private Role role;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "password_record", length = 512)
    private String passwordRecord;

    @Column(name = "password_change_required", nullable = false)
    private boolean passwordChangeRequired;

    @Column(name = "mfa_required", nullable = false)
    private boolean mfaRequired = true;

    @Column(name = "mfa_enabled", nullable = false)
    private boolean mfaEnabled;

    @Column(name = "totp_secret", length = 255)
    private String totpSecret;

    @Column(name = "last_accepted_step", nullable = false)
    private long lastAcceptedStep = -1;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "security_stamp", nullable = false, length = 32)
    private String securityStamp = newStamp();

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "erased_at")
    private Instant erasedAt;

    @Version
    private long version;

    protected AppUser() {
    }

    public AppUser(String username, String displayName, String email, Role role, Instant now) {
        this.username = username;
        this.displayName = displayName;
        this.email = email;
        this.role = role;
        this.createdAt = now;
        this.updatedAt = now;
    }

    /** SR-01: mandatory for agents and administrators, on by default for requesters. */
    public boolean mfaMandatory() {
        return role.alwaysRequiresMfa() || mfaRequired;
    }

    public boolean isErased() {
        return erasedAt != null;
    }

    public boolean canSignIn() {
        return enabled && !isErased() && passwordRecord != null;
    }

    /**
     * Ends every existing session of this account at its next request: role change, disable,
     * password change and MFA reset all call this (SC-01: rotation on privilege change).
     */
    public void rotateSecurityStamp(Instant now) {
        this.securityStamp = newStamp();
        touch(now);
    }

    public void touch(Instant now) {
        this.updatedAt = now;
    }

    private static String newStamp() {
        byte[] raw = new byte[16];
        RANDOM.nextBytes(raw);
        return HexFormat.of().formatHex(raw);
    }

    // ---- MFA -----------------------------------------------------------------------------------

    /** Enrolment begun: the secret is stored, but the factor stays off until a code confirms it. */
    public void startEnrolment(String sealedSecret, Instant now) {
        this.totpSecret = sealedSecret;
        this.mfaEnabled = false;
        this.lastAcceptedStep = -1;
        touch(now);
    }

    public void confirmEnrolment(long acceptedStep, Instant now) {
        this.mfaEnabled = true;
        this.lastAcceptedStep = acceptedStep;
        touch(now);
    }

    public void removeSecondFactor(Instant now) {
        this.totpSecret = null;
        this.mfaEnabled = false;
        this.lastAcceptedStep = -1;
        rotateSecurityStamp(now);
    }

    // ---- erasure (SR-10) ------------------------------------------------------------------------

    /**
     * Removes the personal data and every credential; the row stays so that comments on other
     * people's tickets and audit references still resolve, but to nobody in particular.
     */
    public void erase(Instant now) {
        String marker = getId().toString().substring(0, 8);
        this.username = "erased-" + marker;
        this.displayName = "Erased user";
        this.email = null;
        this.enabled = false;
        this.passwordRecord = null;
        this.passwordChangeRequired = false;
        this.totpSecret = null;
        this.mfaEnabled = false;
        this.lastAcceptedStep = -1;
        this.erasedAt = now;
        rotateSecurityStamp(now);
    }

    // ---- accessors -----------------------------------------------------------------------------

    public String getUsername() {
        return username;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getEmail() {
        return email;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getPasswordRecord() {
        return passwordRecord;
    }

    public void setPasswordRecord(String passwordRecord) {
        this.passwordRecord = passwordRecord;
    }

    public boolean isPasswordChangeRequired() {
        return passwordChangeRequired;
    }

    public void setPasswordChangeRequired(boolean passwordChangeRequired) {
        this.passwordChangeRequired = passwordChangeRequired;
    }

    public boolean isMfaRequired() {
        return mfaRequired;
    }

    public void setMfaRequired(boolean mfaRequired) {
        this.mfaRequired = mfaRequired;
    }

    public boolean isMfaEnabled() {
        return mfaEnabled;
    }

    public String getTotpSecret() {
        return totpSecret;
    }

    public void setTotpSecret(String totpSecret) {
        this.totpSecret = totpSecret;
    }

    public long getLastAcceptedStep() {
        return lastAcceptedStep;
    }

    public void setLastAcceptedStep(long lastAcceptedStep) {
        this.lastAcceptedStep = lastAcceptedStep;
    }

    public String getSecurityStamp() {
        return securityStamp;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public Instant getErasedAt() {
        return erasedAt;
    }
}
