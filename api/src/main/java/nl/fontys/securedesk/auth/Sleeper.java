package nl.fontys.securedesk.auth;

import java.time.Duration;

/**
 * The progressive delay. Requests run on virtual threads, so sleeping here holds no platform
 * thread, which was the limit the mfa-poc wrote down for its own delay. Tests replace the bean
 * with one that records the delays instead of waiting for them.
 */
public interface Sleeper {

    void sleep(Duration duration);

    static Sleeper threadSleep() {
        return duration -> {
            if (duration.isZero() || duration.isNegative()) {
                return;
            }
            try {
                Thread.sleep(duration);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        };
    }
}
