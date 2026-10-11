package nl.fontys.securedesk.audit;

/**
 * What an event is about (BoK 5.3.2). Rules, alerts and retention select on the category and
 * the outcome, never on the log level: a failed login is routine for operations and important
 * for security, which the Windows and syslog demonstrations of 6.2 showed.
 */
public enum AuditCategory {
    /** Sign-in, second factor, sessions and credentials. */
    AUTHN,
    /** Refused requests: function level, object level, CSRF, step-up. */
    AUTHZ,
    /** Higher-risk functionality: user administration and privilege changes. */
    ACCOUNT,
    /** Configuration changes. */
    CONFIG,
    /** Tickets, comments and attachments. */
    DATA,
    /** Retention and erasure. */
    PRIVACY,
    /** Access to and integrity of the audit trail itself. */
    AUDIT,
    /** Start-up, shut-down, key rotation, notifications. */
    SYSTEM,
    /** Input validation failures. */
    INPUT
}
