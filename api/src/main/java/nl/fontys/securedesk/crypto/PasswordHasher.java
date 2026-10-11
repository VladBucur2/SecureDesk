package nl.fontys.securedesk.crypto;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.Semaphore;

/**
 * What SecureDesk does with a password at registration and at login: the {@code PasswordStore}
 * of the password-storage PoC (BoK 6.3), with the user table replaced by the caller's entity.
 * Every value that leaves this class is a sealed record; the plain Argon2id record exists only
 * inside it.
 */
@Service
public class PasswordHasher {

    public enum Outcome {
        /** Password correct. */
        OK,
        /** Password correct, and the stored hash must be replaced by {@link Check#upgradedRecord()}. */
        OK_REHASHED,
        /** Wrong password; the caller answers with the same generic failure as for an unknown user. */
        FAILED,
        /** The stored value could not be opened: someone changed the table. Answer the user as
         *  FAILED, but log it as a security event with an alert. */
        TAMPERED
    }

    /** The result of a verification; {@code upgradedRecord} is set only for OK_REHASHED. */
    public record Check(Outcome outcome, String upgradedRecord) {
        public boolean matched() {
            return outcome == Outcome.OK || outcome == Outcome.OK_REHASHED;
        }
    }

    private final Pepper pepper;
    private final SecureRandom random = new SecureRandom();
    private final Semaphore argon2Slots;
    private final StoredHash dummy;

    public PasswordHasher(Pepper pepper, CryptoProperties properties) {
        this.pepper = pepper;
        this.argon2Slots = new Semaphore(Math.max(1, properties.argon2MaxConcurrent()), true);
        // A hash of random bytes. Checking a login for an unknown user against it costs the same as
        // checking a real user, so the response time does not reveal which accounts exist.
        byte[] randomPassword = new byte[32];
        random.nextBytes(randomPassword);
        this.dummy = newHash(randomPassword, PasswordPolicy.CURRENT);
    }

    /** Registration or password change. The caller has already applied {@link PasswordPolicy#accept}. */
    public String newPasswordRecord(UUID userId, String acceptedPassword) {
        return pepper.sealPassword(userId, newHash(acceptedPassword, PasswordPolicy.CURRENT).format());
    }

    /** Login: verify the password, and hand back an upgraded record if it uses older parameters. */
    public Check verifyPassword(UUID userId, String sealedRecord, String password) {
        String normalised = PasswordPolicy.normalise(password == null ? "" : password);
        if (PasswordPolicy.length(normalised) > PasswordPolicy.MAX_LENGTH) {
            return new Check(Outcome.FAILED, null);   // could never have been stored; not worth a hash
        }
        if (sealedRecord == null) {                   // an erased account has no record at all
            matches(dummy, normalised);
            return new Check(Outcome.FAILED, null);
        }
        StoredHash record;
        try {
            record = StoredHash.parse(pepper.openPassword(userId, sealedRecord));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            matches(dummy, normalised);
            return new Check(Outcome.TAMPERED, null);
        }
        if (!matches(record, normalised)) {
            return new Check(Outcome.FAILED, null);
        }
        if (needsRehash(record)) {
            // The one moment the plaintext is available again: hash it under the current policy.
            return new Check(Outcome.OK_REHASHED, newPasswordRecord(userId, normalised));
        }
        return new Check(Outcome.OK, null);
    }

    /** Spends the same work as a real verification, for a login whose account does not exist. */
    public void verifyAgainstDummy(String password) {
        String normalised = PasswordPolicy.normalise(password == null ? "" : password);
        if (PasswordPolicy.length(normalised) <= PasswordPolicy.MAX_LENGTH) {
            matches(dummy, normalised);
        }
    }

    /** A recovery code is a credential: Argon2id with its own salt, sealed to its own row id. */
    public String newRecoveryCodeRecord(UUID codeId, String normalisedCode) {
        return pepper.sealRecoveryCode(codeId, newHash(normalisedCode, PasswordPolicy.CURRENT).format());
    }

    public Outcome verifyRecoveryCode(UUID codeId, String sealedRecord, String normalisedCode) {
        StoredHash record;
        try {
            record = StoredHash.parse(pepper.openRecoveryCode(codeId, sealedRecord));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return Outcome.TAMPERED;
        }
        return matches(record, normalisedCode) ? Outcome.OK : Outcome.FAILED;
    }

    static boolean needsRehash(StoredHash record) {
        return !record.params().equals(PasswordPolicy.CURRENT)
                || record.salt().length < PasswordPolicy.SALT_BYTES
                || record.hash().length < PasswordPolicy.HASH_BYTES;
    }

    // ---- hashing and comparing -----------------------------------------------------------------

    /** Package-private for the tests that store a record under older parameters. */
    StoredHash newHash(String normalised, Argon2id.Params params) {
        byte[] bytes = normalised.getBytes(StandardCharsets.UTF_8);
        try {
            return newHash(bytes, params);
        } finally {
            Arrays.fill(bytes, (byte) 0);       // do not leave the password in memory longer than needed
        }
    }

    private StoredHash newHash(byte[] password, Argon2id.Params params) {
        byte[] salt = new byte[PasswordPolicy.SALT_BYTES];
        random.nextBytes(salt);                 // from a CSPRNG, new for every password
        return new StoredHash(params, salt, argon2(password, salt, params, PasswordPolicy.HASH_BYTES));
    }

    /** Recomputes the hash with the stored salt and parameters, then compares in constant time. */
    private boolean matches(StoredHash record, String normalised) {
        byte[] bytes = normalised.getBytes(StandardCharsets.UTF_8);
        try {
            byte[] candidate = argon2(bytes, record.salt(), record.params(), record.hash().length);
            return MessageDigest.isEqual(candidate, record.hash());
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /**
     * Every computation fills 19 MiB. The semaphore caps how many run at once, which the PoC
     * named as the open availability risk: a flood of logins would otherwise exhaust the heap.
     * Requests run on virtual threads, so waiting for a slot costs no platform thread.
     */
    private byte[] argon2(byte[] password, byte[] salt, Argon2id.Params params, int length) {
        argon2Slots.acquireUninterruptibly();
        try {
            return Argon2id.hash(password, salt, params, length);
        } finally {
            argon2Slots.release();
        }
    }
}
