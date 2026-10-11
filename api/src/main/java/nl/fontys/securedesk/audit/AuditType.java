package nl.fontys.securedesk.audit;

import static nl.fontys.securedesk.audit.AuditCategory.ACCOUNT;
import static nl.fontys.securedesk.audit.AuditCategory.AUDIT;
import static nl.fontys.securedesk.audit.AuditCategory.AUTHN;
import static nl.fontys.securedesk.audit.AuditCategory.AUTHZ;
import static nl.fontys.securedesk.audit.AuditCategory.CONFIG;
import static nl.fontys.securedesk.audit.AuditCategory.DATA;
import static nl.fontys.securedesk.audit.AuditCategory.INPUT;
import static nl.fontys.securedesk.audit.AuditCategory.PRIVACY;
import static nl.fontys.securedesk.audit.AuditCategory.SYSTEM;

/**
 * The event catalogue of SecureDesk (BoK 5.3.5): every event the application writes, its
 * category, whether it carries the alert flag, and why it exists. docs/event-catalogue.md is
 * this list in prose; a test keeps the two in step.
 *
 * <p>An alert event is one a SIEM should page on by itself: it is either what an attacker with
 * a foothold would do next (reset a factor, change a role), or evidence that a control was
 * attacked (a tampered credential, a broken hash chain).
 */
public enum AuditType {

    // ---- authentication (MU-01, MU-02) --------------------------------------------------------
    LOGIN_PASSWORD(AUTHN, false, "Password step of the sign-in, success or failure"),
    LOGIN_BLOCKED(AUTHN, false, "Sign-in attempt for a username that is locked"),
    ACCOUNT_LOCKED(AUTHN, true, "Ten failed attempts within fifteen minutes; the username is locked"),
    MFA_VERIFY(AUTHN, false, "Code step of the sign-in, with method or running failure count"),
    MFA_RECOVERY_USED(AUTHN, true, "A single-use recovery code was spent"),
    MFA_ENROL_START(AUTHN, false, "A new TOTP secret was generated for enrolment"),
    MFA_ENROL_CONFIRM(AUTHN, false, "Enrolment confirmed with a code from the new generator, or refused"),
    RECOVERY_CODES_ISSUED(AUTHN, false, "Ten recovery codes were issued and shown once"),
    LOGIN_COMPLETE(AUTHN, false, "Fully signed in, with the number of factors used"),
    REAUTH(AUTHN, false, "Step-up authentication before an administrative action"),
    LOGOUT(AUTHN, false, "Signed out"),
    SESSION_REVOKED(AUTHN, false, "Session ended because the account changed (role, disable, reset, password)"),
    SESSION_EXPIRED(AUTHN, false, "Session ended at its absolute lifetime"),
    PASSWORD_CHANGED(AUTHN, false, "The account's password was changed by its owner"),
    PASSWORD_REJECTED(AUTHN, false, "A new password was refused by the policy, with the reason"),
    PASSWORD_REHASHED(AUTHN, false, "A password hash under older parameters was upgraded at sign-in"),
    CREDENTIAL_TAMPERED(AUTHN, true, "A stored credential failed its integrity check: the table was changed"),

    // ---- authorisation (MU-03, MU-06) ---------------------------------------------------------
    AUTHZ_DENIED(AUTHZ, false, "Request refused by a role check (403)"),
    CSRF_DENIED(AUTHZ, false, "Request refused for a missing or wrong CSRF token (403)"),
    OBJECT_ACCESS_DENIED(AUTHZ, false, "A ticket or attachment outside the caller's reach was requested (404)"),
    REAUTH_REQUIRED(AUTHZ, false, "An administrative action was refused until the user re-authenticates"),

    // ---- account administration (UC-05, MU-06) ------------------------------------------------
    USER_CREATED(ACCOUNT, false, "An administrator created an account"),
    USER_ROLE_CHANGED(ACCOUNT, true, "An account's role was changed, with the old and new role"),
    USER_DISABLED(ACCOUNT, true, "An account was disabled"),
    USER_ENABLED(ACCOUNT, false, "An account was enabled again"),
    MFA_RESET(ACCOUNT, true, "An administrator removed an account's second factor"),
    MFA_REQUIREMENT_CHANGED(ACCOUNT, true, "The second factor was made optional or mandatory for a requester"),
    PASSWORD_RESET_BY_ADMIN(ACCOUNT, true, "An administrator issued a temporary password"),
    USER_ERASED(PRIVACY, true, "An account's personal data and tickets were erased (SR-10)"),

    // ---- configuration (UC-06) ----------------------------------------------------------------
    CATEGORY_CREATED(CONFIG, false, "A ticket category was added"),
    CATEGORY_UPDATED(CONFIG, false, "A ticket category was renamed, activated or deactivated"),
    RETENTION_CHANGED(CONFIG, true, "The retention period was changed, with the old and new value"),

    // ---- tickets (UC-02 to UC-04) -------------------------------------------------------------
    TICKET_CREATED(DATA, false, "A ticket was filed"),
    TICKET_UPDATED(DATA, false, "Status, priority, assignee or resolution changed, with the fields"),
    COMMENT_ADDED(DATA, false, "A comment or internal note was added (never its text)"),
    ATTACHMENT_UPLOADED(DATA, false, "A file passed inspection and was stored, with type and size"),
    ATTACHMENT_DOWNLOADED(DATA, false, "An attachment was downloaded"),
    UPLOAD_REJECTED(DATA, false, "An upload was refused, with the reason"),

    // ---- privacy (SC-11) ----------------------------------------------------------------------
    RETENTION_PURGE(PRIVACY, false, "Closed tickets past the retention period were deleted, with the count"),

    // ---- the audit trail itself (UC-07, MU-08) ------------------------------------------------
    AUDIT_LOG_VIEWED(AUDIT, false, "An administrator read the audit log, with the filter used"),
    AUDIT_CHAIN_VERIFIED(AUDIT, false, "The hash chain was verified intact up to a sequence number"),
    AUDIT_CHAIN_BROKEN(AUDIT, true, "The hash chain is broken: a row was altered or removed"),

    // ---- system (OWASP: start-ups, shut-downs, logging initialisation) -------------------------
    APP_STARTED(SYSTEM, false, "The API started; the first event after logging initialisation"),
    APP_STOPPING(SYSTEM, false, "The API is shutting down"),
    KEYS_ROTATED(SYSTEM, false, "Stored credentials were re-sealed under the current keys, with counts"),
    NOTIFICATION_SENT(SYSTEM, false, "A ticket-change mail was sent (ticket number only)"),
    NOTIFICATION_FAILED(SYSTEM, false, "A ticket-change mail could not be sent"),

    // ---- input (OWASP: input validation failures) ----------------------------------------------
    INPUT_VALIDATION_FAILED(INPUT, false, "A request was refused by validation, with field names only");

    private final AuditCategory category;
    private final boolean alert;
    private final String purpose;

    AuditType(AuditCategory category, boolean alert, String purpose) {
        this.category = category;
        this.alert = alert;
        this.purpose = purpose;
    }

    public AuditCategory category() {
        return category;
    }

    public boolean alert() {
        return alert;
    }

    public String purpose() {
        return purpose;
    }
}
