package nl.fontys.securedesk.user;

import nl.fontys.securedesk.audit.AuditLog;
import nl.fontys.securedesk.auth.RecoveryCodeRepository;
import nl.fontys.securedesk.common.ApiException;
import nl.fontys.securedesk.crypto.PasswordHasher;
import nl.fontys.securedesk.crypto.PasswordPolicy;
import nl.fontys.securedesk.ticket.TicketErasure;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** The last enabled administrator cannot be disabled, demoted or erased: the system stays administrable. */
class LastAdministratorTest {

    private final AppUserRepository users = mock(AppUserRepository.class);
    private final UserAdminService service = new UserAdminService(users, mock(RecoveryCodeRepository.class),
            mock(PasswordHasher.class), mock(PasswordPolicy.class), mock(TicketErasure.class), mock(AuditLog.class),
            Clock.systemUTC());

    @Test
    @DisplayName("refused when only one enabled administrator is left")
    void lastAdminIsKept() {
        AppUser only = new AppUser("root", "Root", null, Role.ADMIN, Instant.now());
        when(users.findById(only.getId())).thenReturn(Optional.of(only));
        when(users.countByRoleAndEnabledTrueAndErasedAtIsNull(Role.ADMIN)).thenReturn(1L);

        assertThatThrownBy(() -> service.setEnabled(only.getId(), false))
                .isInstanceOf(ApiException.class).hasMessageContaining("last enabled administrator");
        assertThatThrownBy(() -> service.changeRole(only.getId(), Role.AGENT)).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> service.erase(only.getId())).isInstanceOf(ApiException.class);
        assertThat(only.isEnabled()).isTrue();
        assertThat(only.getRole()).isEqualTo(Role.ADMIN);
    }
}
