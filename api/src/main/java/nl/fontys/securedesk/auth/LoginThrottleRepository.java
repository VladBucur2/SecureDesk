package nl.fontys.securedesk.auth;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

public interface LoginThrottleRepository extends JpaRepository<LoginThrottle, String> {

    /** Row lock, so two parallel failures for one username are both counted. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select t from LoginThrottle t where t.usernameKey = :key")
    Optional<LoginThrottle> findForUpdate(@Param("key") String key);

    @Modifying
    @Query("delete from LoginThrottle t where t.lastFailureAt < :before and (t.lockedUntil is null or t.lockedUntil < :now)")
    int deleteExpired(@Param("before") Instant before, @Param("now") Instant now);
}
