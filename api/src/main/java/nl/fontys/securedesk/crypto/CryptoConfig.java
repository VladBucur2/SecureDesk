package nl.fontys.securedesk.crypto;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CryptoConfig {

    /** Loaded once: the 100,000 most common breached passwords (NCSC list via SecLists). */
    @Bean
    public PasswordPolicy passwordPolicy() {
        return PasswordPolicy.withBundledBlocklist();
    }
}
