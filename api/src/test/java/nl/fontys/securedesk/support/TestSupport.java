package nl.fontys.securedesk.support;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.time.Instant;

@TestConfiguration
public class TestSupport {

    /** Start in the middle of a 30-second step, so a test never straddles a step by accident. */
    @Bean
    @Primary
    public MutableClock testClock() {
        return new MutableClock(Instant.parse("2026-10-12T09:00:15Z"));
    }

    @Bean
    @Primary
    public RecordingSleeper recordingSleeper() {
        return new RecordingSleeper();
    }
}
