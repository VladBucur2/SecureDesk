package nl.fontys.securedesk.auth;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Optional;

/**
 * Anti-automation per account (SC-02): a progressive delay and a temporary lock. It is keyed by
 * the submitted username, not by the account, so an unknown username is delayed and locked
 * exactly like a real one and the behaviour reveals nothing about which accounts exist.
 *
 * <p>Failures are counted in a transaction of their own, so a failure is recorded even when the
 * request that caused it is answered with an error.
 */
@Service
public class LoginThrottleService {

    public record State(boolean locked, int failures, Duration delay) {
    }

    private final LoginThrottleRepository repository;
    private final AuthProperties.Lockout policy;
    private final Clock clock;
    private final TransactionTemplate newTransaction;

    public LoginThrottleService(LoginThrottleRepository repository, AuthProperties properties, Clock clock,
                                PlatformTransactionManager transactionManager) {
        this.repository = repository;
        this.policy = properties.lockout();
        this.clock = clock;
        this.newTransaction = new TransactionTemplate(transactionManager);
        this.newTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    /**
     * The key for a username as typed: NFC, trimmed, lower case. Anything longer than the column
     * is replaced by its SHA-256, so an absurd username still has a stable key of fixed length.
     */
    public static String keyFor(String username) {
        String normalised = normalise(username);
        if (normalised.length() <= 64) {
            return normalised;
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(normalised.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A username as stored: NFC, trimmed, lower case. */
    public static String normalise(String username) {
        return Normalizer.normalize(username == null ? "" : username, Normalizer.Form.NFC)
                .strip().toLowerCase(Locale.ROOT);
    }

    public State state(String key) {
        Instant now = clock.instant();
        Optional<LoginThrottle> row = newTransaction.execute(status -> repository.findById(key));
        if (row == null || row.isEmpty()) {
            return new State(false, 0, Duration.ZERO);
        }
        int failures = row.get().activeFailures(now, policy.window());
        return new State(row.get().isLocked(now), failures, policy.delayAfter(failures));
    }

    /** Counts a failure. Returns the state after it; {@code locked} is true if this one locked it. */
    public State recordFailure(String key) {
        for (int attempt = 1; ; attempt++) {
            try {
                return newTransaction.execute(status -> {
                    Instant now = clock.instant();
                    LoginThrottle row = repository.findForUpdate(key).orElseGet(() -> new LoginThrottle(key, now));
                    boolean lockedNow = row.recordFailure(now, policy);
                    repository.saveAndFlush(row);
                    return new State(lockedNow, lockedNow ? policy.maxFailures() : row.getFailureCount(),
                            policy.delayAfter(row.getFailureCount()));
                });
            } catch (DataIntegrityViolationException e) {
                // Two first failures for the same key raced to insert the row; the second retry
                // finds it and locks it like any other.
                if (attempt >= 2) {
                    throw e;
                }
            }
        }
    }

    /** A complete sign-in clears the record. A correct password alone does not (see AuthService). */
    public void recordSuccess(String key) {
        newTransaction.executeWithoutResult(status -> repository.findById(key).ifPresent(repository::delete));
    }

    public int maxFailures() {
        return policy.maxFailures();
    }

    @Scheduled(fixedDelayString = "PT10M", initialDelayString = "PT10M")
    void purgeExpired() {
        Instant now = clock.instant();
        newTransaction.executeWithoutResult(status -> repository.deleteExpired(now.minus(policy.window()), now));
    }
}
