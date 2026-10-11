package nl.fontys.securedesk.crypto;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * The one place that calls the Argon2 algorithm itself (taken over unchanged from the
 * password-storage PoC, BoK 6.3). The algorithm comes from BouncyCastle: everything around it
 * (salt, parameters, storage format, verification, upgrades, pepper) is this project's own code,
 * but the primitive is not something to write yourself.
 */
public final class Argon2id {

    /**
     * The cost parameters, which are stored with every hash.
     *
     * @param memoryKiB   memory one hash computation fills, in KiB (19456 KiB = 19 MiB)
     * @param iterations  number of passes over that memory
     * @param parallelism number of lanes that can be computed in parallel
     */
    public record Params(int memoryKiB, int iterations, int parallelism) {
        @Override
        public String toString() {
            return "m=" + memoryKiB + ",t=" + iterations + ",p=" + parallelism;
        }
    }

    private Argon2id() {
    }

    /** Argon2id over the password bytes with the given salt and cost parameters. */
    public static byte[] hash(byte[] password, byte[] salt, Params params, int hashLength) {
        return compute(password, salt, params, hashLength, null, null);
    }

    /**
     * The full function of RFC 9106, including the optional secret value and associated data.
     * The application never uses those two inputs; the unit test needs them to reproduce the
     * official test vector of RFC 9106, section 5.3.
     */
    static byte[] compute(byte[] password, byte[] salt, Params params, int hashLength,
                          byte[] secret, byte[] associatedData) {
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)   // 0x13 = 19, the current version
                .withMemoryAsKB(params.memoryKiB())
                .withIterations(params.iterations())
                .withParallelism(params.parallelism())
                .withSalt(salt);
        if (secret != null) {
            builder.withSecret(secret);
        }
        if (associatedData != null) {
            builder.withAdditional(associatedData);
        }
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(builder.build());
        byte[] out = new byte[hashLength];
        generator.generateBytes(password, out);
        return out;
    }
}
