package nl.fontys.securedesk.auth;

/**
 * The stages a sign-in passes after the password, in this order:
 *
 * <ol>
 *   <li>MFA: a code, when a factor is enrolled. It comes first so that a temporary password
 *       alone can never be used to set a new password on an account that has a factor;</li>
 *   <li>PASSWORD_CHANGE: when an administrator issued a temporary password;</li>
 *   <li>ENROL: when a factor is mandatory but none is enrolled yet. It comes after the password
 *       change, so whoever knew the temporary password cannot enrol a device of their own on an
 *       account they will no longer be able to open.</li>
 * </ol>
 */
public enum AuthStage {
    MFA,
    PASSWORD_CHANGE,
    ENROL
}
