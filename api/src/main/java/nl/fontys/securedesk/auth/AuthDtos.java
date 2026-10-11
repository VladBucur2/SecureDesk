package nl.fontys.securedesk.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import nl.fontys.securedesk.user.Role;

import java.util.List;
import java.util.UUID;

/** Request and response bodies of /api/auth. Requests carry exactly the fields below, no more. */
public final class AuthDtos {

    private AuthDtos() {
    }

    /** The password limit is generous on purpose: anything over 128 characters fails without a hash. */
    public record LoginRequest(@NotBlank @Size(max = 128) String username,
                               @NotNull @Size(max = 1024) String password) {
        /** A record prints every field by default; a debug log line must never show the password. */
        @Override
        public String toString() {
            return "LoginRequest[username=" + username + ", password=<redacted>]";
        }
    }

    public record CodeRequest(@NotBlank @Size(max = 32) String code) {
        @Override
        public String toString() {
            return "CodeRequest[code=<redacted>]";
        }
    }

    public record NewPasswordRequest(@NotNull @Size(max = 1024) String newPassword) {
        @Override
        public String toString() {
            return "NewPasswordRequest[newPassword=<redacted>]";
        }
    }

    /**
     * Where the session stands. {@code csrfToken} is the session's synchroniser token: the SPA
     * keeps it in memory and sends it as X-XSRF-TOKEN with every state-changing request.
     */
    public record SessionState(String stage, Me user, String pendingUsername, String csrfToken) {
    }

    public record Me(UUID id, String username, String displayName, Role role, boolean mfaEnabled,
                     boolean mfaMandatory, long recoveryCodesLeft) {
    }

    public record StageResponse(String stage) {
    }

    public record Enrolment(String secret, String otpauthUri, String issuer, String account) {
    }

    /** The recovery codes appear in this one response and nowhere else, ever. */
    public record EnrolmentDone(String stage, List<String> recoveryCodes) {
    }
}
