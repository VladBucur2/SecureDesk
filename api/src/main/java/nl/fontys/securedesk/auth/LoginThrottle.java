package nl.fontys.securedesk.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.springframework.data.domain.Persistable;

import java.time.Duration;
import java.time.Instant;

/** Failed attempts for one submitted username inside the current window. */
@Entity
@Table(name = "login_throttle")
public class LoginThrottle implements Persistable<String> {

    @Id
    @Column(name = "username_key", length = 64)
    private String usernameKey;

    @Column(name = "failure_count", nullable = false)
    private int failureCount;

    @Column(name = "window_start", nullable = false)
    private Instant windowStart;

    @Column(name = "last_failure_at", nullable = false)
    private Instant lastFailureAt;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @jakarta.persistence.Transient
    private boolean fresh;

    protected LoginThrottle() {
    }

    LoginThrottle(String usernameKey, Instant now) {
        this.usernameKey = usernameKey;
        this.windowStart = now;
        this.lastFailureAt = now;
        this.fresh = true;
    }

    boolean isLocked(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }

    /** Failures that still count: none once the window has passed. */
    int activeFailures(Instant now, Duration window) {
        return windowStart.plus(window).isAfter(now) ? failureCount : 0;
    }

    /** Records one failure; returns true when this failure locks the username. */
    boolean recordFailure(Instant now, AuthProperties.Lockout policy) {
        if (!windowStart.plus(policy.window()).isAfter(now)) {
            failureCount = 0;
            windowStart = now;
        }
        failureCount++;
        lastFailureAt = now;
        if (failureCount >= policy.maxFailures()) {
            lockedUntil = now.plus(policy.duration());
            failureCount = 0;
            windowStart = now;
            return true;
        }
        return false;
    }

    int getFailureCount() {
        return failureCount;
    }

    @Override
    public String getId() {
        return usernameKey;
    }

    @Override
    public boolean isNew() {
        return fresh;
    }
}
