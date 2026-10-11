package nl.fontys.securedesk.auth;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface RecoveryCodeRepository extends JpaRepository<RecoveryCode, UUID> {

    List<RecoveryCode> findByUserIdAndUsedAtIsNull(UUID userId);

    long countByUserIdAndUsedAtIsNull(UUID userId);

    @Transactional
    @Modifying
    @Query("delete from RecoveryCode c where c.userId = :userId")
    int deleteByUserId(@Param("userId") UUID userId);

    /** Spends a code; returns 0 if it was already spent, so a code works once even under a race. */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("update RecoveryCode c set c.usedAt = :now where c.id = :id and c.usedAt is null")
    int markUsed(@Param("id") UUID id, @Param("now") Instant now);
}
