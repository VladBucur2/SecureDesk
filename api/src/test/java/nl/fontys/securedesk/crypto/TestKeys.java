package nl.fontys.securedesk.crypto;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/** Random keyrings for unit tests, generated per run like the PoC's in-memory pepper. */
public final class TestKeys {

    private static final SecureRandom RANDOM = new SecureRandom();

    private TestKeys() {
    }

    public static String randomKey() {
        byte[] raw = new byte[32];
        RANDOM.nextBytes(raw);
        return Base64.getEncoder().encodeToString(raw);
    }

    public static CryptoProperties.KeyRing ring(String current, String... ids) {
        Map<String, String> keys = new LinkedHashMap<>();
        for (String id : ids) {
            keys.put(id, randomKey());
        }
        return new CryptoProperties.KeyRing(current, keys);
    }

    public static CryptoProperties properties() {
        return new CryptoProperties(ring("k1", "k1"), ring("k1", "k1"), 2);
    }
}
