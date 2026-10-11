package nl.fontys.securedesk.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.UUID;

/** Bodies of /api/admin/users and /api/account. */
public final class UserDtos {

    private UserDtos() {
    }

    public record CreateUserRequest(
            @NotBlank @Pattern(regexp = "[a-z][a-z0-9._-]{2,31}") String username,
            @NotBlank @Size(max = 100) String displayName,
            @Email @Size(max = 254) String email,
            @NotNull Role role,
            Boolean mfaRequired) {
    }

    public record RoleRequest(@NotNull Role role) {
    }

    public record EnabledRequest(@NotNull Boolean enabled) {
    }

    public record MfaRequiredRequest(@NotNull Boolean required) {
    }

    public record ChangePasswordRequest(@NotNull @Size(max = 1024) String currentPassword,
                                        @NotNull @Size(max = 1024) String newPassword) {
        @Override
        public String toString() {
            return "ChangePasswordRequest[<redacted>]";
        }
    }

    public record UserView(UUID id, String username, String displayName, String email, Role role,
                           boolean enabled, boolean mfaEnabled, boolean mfaMandatory, boolean mfaRequired,
                           boolean passwordChangeRequired, boolean erased, Instant createdAt) {

        public static UserView of(AppUser user) {
            return new UserView(user.getId(), user.getUsername(), user.getDisplayName(), user.getEmail(),
                    user.getRole(), user.isEnabled(), user.isMfaEnabled(), user.mfaMandatory(),
                    user.isMfaRequired(), user.isPasswordChangeRequired(), user.isErased(), user.getCreatedAt());
        }
    }

    /** The temporary password appears in this one response; it is never stored or logged. */
    public record TemporaryPasswordView(UserView user, String temporaryPassword) {
    }

    public record RecoveryCodesView(java.util.List<String> recoveryCodes) {
    }
}
