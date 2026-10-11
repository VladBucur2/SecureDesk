package nl.fontys.securedesk.crypto;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * One stored password in the PHC string format, the same format Spring Security, libsodium and
 * the Argon2 reference implementation use:
 *
 * <pre>$argon2id$v=19$m=19456,t=2,p=1$&lt;salt in base64&gt;$&lt;hash in base64&gt;</pre>
 *
 * Algorithm, version and cost parameters travel with every hash, so a hash made under an older
 * policy can still be verified and then recognised as due for an upgrade.
 *
 * <p>Compared with the PoC, parsing also bounds the cost parameters. The record is authenticated
 * by the pepper before it is parsed, so this is defence in depth: a record that somehow asked
 * for gigabytes of memory would otherwise turn one login into a denial of service.
 */
public record StoredHash(Argon2id.Params params, byte[] salt, byte[] hash) {

    private static final Base64.Encoder ENCODER = Base64.getEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getDecoder();

    static final int MAX_MEMORY_KIB = 1_048_576;   // 1 GiB
    static final int MAX_ITERATIONS = 16;
    static final int MAX_PARALLELISM = 16;

    public String format() {
        return "$argon2id$v=19$" + params + "$" + ENCODER.encodeToString(salt)
                + "$" + ENCODER.encodeToString(hash);
    }

    public static StoredHash parse(String value) {
        // "$argon2id$v=19$m=19456,t=2,p=1$salt$hash" splits into "", "argon2id", "v=19", ...
        String[] parts = value.split("\\$");
        if (parts.length != 6 || !parts[0].isEmpty()
                || !"argon2id".equals(parts[1]) || !"v=19".equals(parts[2])) {
            throw new IllegalArgumentException("not an Argon2id version 19 record");
        }
        Map<String, Integer> cost = new HashMap<>();
        for (String pair : parts[3].split(",")) {
            String[] keyValue = pair.split("=", 2);
            if (keyValue.length != 2) {
                throw new IllegalArgumentException("malformed cost parameters");
            }
            cost.put(keyValue[0], Integer.parseInt(keyValue[1]));
        }
        if (!cost.keySet().equals(Set.of("m", "t", "p"))) {
            throw new IllegalArgumentException("expected exactly m, t and p");
        }
        Argon2id.Params params = new Argon2id.Params(cost.get("m"), cost.get("t"), cost.get("p"));
        if (params.parallelism() < 1 || params.parallelism() > MAX_PARALLELISM
                || params.iterations() < 1 || params.iterations() > MAX_ITERATIONS
                || params.memoryKiB() < 8 * params.parallelism() || params.memoryKiB() > MAX_MEMORY_KIB) {
            throw new IllegalArgumentException("cost parameters out of bounds");
        }
        byte[] salt = DECODER.decode(parts[4]);
        byte[] hash = DECODER.decode(parts[5]);
        if (salt.length < 8 || hash.length < 16 || hash.length > 64) {
            throw new IllegalArgumentException("salt or hash length out of bounds");
        }
        return new StoredHash(params, salt, hash);
    }
}
