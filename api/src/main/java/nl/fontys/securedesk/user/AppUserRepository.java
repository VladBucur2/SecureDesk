package nl.fontys.securedesk.user;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AppUserRepository extends JpaRepository<AppUser, UUID> {

    Optional<AppUser> findByUsername(String username);

    boolean existsByUsername(String username);

    Page<AppUser> findAllByOrderByUsernameAsc(Pageable pageable);

    List<AppUser> findByRoleAndEnabledTrueAndErasedAtIsNullOrderByDisplayNameAsc(Role role);

    long countByRoleAndEnabledTrueAndErasedAtIsNull(Role role);

    /**
     * Records an accepted TOTP step, but only if it is newer than the last one. Two requests that
     * race with the same code cannot both win: exactly one update changes the row (BoK 6.1 case 4).
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("update AppUser u set u.lastAcceptedStep = :step where u.id = :id and u.lastAcceptedStep < :step")
    int acceptTotpStep(@Param("id") UUID id, @Param("step") long step);
}
