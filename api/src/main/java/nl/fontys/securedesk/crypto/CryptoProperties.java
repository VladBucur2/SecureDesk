package nl.fontys.securedesk.crypto;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.util.Map;

/**
 * The keys. They arrive as files under /run/secrets/config (Spring's configtree), one file per
 * key, for example {@code securedesk.crypto.pepper.keys.k1}; never from the image, the code or a
 * plain environment file (SR-06). In the reference architecture these files are rendered by
 * the secrets vault of the management zone.
 *
 * @param pepper              keyring for the Argon2id password and recovery-code records
 * @param totp                keyring for the TOTP secrets
 * @param argon2MaxConcurrent how many 19 MiB Argon2id computations may run at the same time;
 *                            the rest wait, so a burst of logins cannot exhaust the heap
 */
@ConfigurationProperties("securedesk.crypto")
public record CryptoProperties(KeyRing pepper, KeyRing totp, @DefaultValue("4") int argon2MaxConcurrent) {

    /**
     * @param current the key id new records are sealed with
     * @param keys    key id to 32 random bytes in Base64; old keys stay until rotation is done
     */
    public record KeyRing(String current, Map<String, String> keys) {
    }
}
