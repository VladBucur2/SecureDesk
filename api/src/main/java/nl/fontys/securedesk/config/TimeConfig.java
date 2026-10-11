package nl.fontys.securedesk.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * One clock for the whole application, always UTC (BoK 5.3.4: trust the clock). Code that needs
 * the time asks for this bean instead of calling Instant.now(), so tests can move time forward to
 * the next TOTP step or past a lockout.
 */
@Configuration
public class TimeConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
