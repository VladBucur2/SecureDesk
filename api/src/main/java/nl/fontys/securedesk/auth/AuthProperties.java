package nl.fontys.securedesk.auth;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;
import java.util.List;

/**
 * @param issuer                  the name an authenticator app shows next to the code
 * @param recentAuthWindow        how long a sign-in or step-up counts as "recent" for
 *                                administrative actions (UC-05)
 * @param absoluteSessionLifetime a session ends after this, however active it is; the idle
 *                                timeout is server.servlet.session.timeout
 * @param lockout                 anti-automation per username (SC-02)
 */
@ConfigurationProperties("securedesk.auth")
public record AuthProperties(
        @DefaultValue("SecureDesk") String issuer,
        @DefaultValue("10m") Duration recentAuthWindow,
        @DefaultValue("8h") Duration absoluteSessionLifetime,
        @DefaultValue Lockout lockout) {

    /**
     * BoK 5.2.3 A: a progressive delay of 0, 1, 2, 4 and 8 seconds, and a lock after ten
     * failures in fifteen minutes. Password, code and step-up failures all count.
     */
    public record Lockout(
            @DefaultValue("10") int maxFailures,
            @DefaultValue("15m") Duration window,
            @DefaultValue("15m") Duration duration,
            @DefaultValue({"0s", "1s", "2s", "4s", "8s"}) List<Duration> delays) {

        public Duration delayAfter(int failures) {
            if (delays.isEmpty()) {
                return Duration.ZERO;
            }
            return delays.get(Math.min(failures, delays.size() - 1));
        }
    }
}
