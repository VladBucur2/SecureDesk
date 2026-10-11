package nl.fontys.securedesk.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * AES-256-GCM under a keyring whose keys live outside the database. This is the {@code Pepper}
 * class of the password-storage PoC (BoK 6.3), generalised so that the same code protects two
 * kinds of record with two separate keyrings: the Argon2id password records (the pepper) and the
 * TOTP secrets (column encryption, SR-05).
 *
 * <p>The associated data binds every record to the row it belongs to. GCM authenticates it
 * without encrypting it, so a record copied into another user's row fails to open, and an
 * attacker who can write to the table cannot plant a record of his own.
 *
 * <p>Stored form: {@code <prefix>:<key id>:<base64 of IV, ciphertext and tag>}. The key id makes
 * rotation possible: records under an old key are opened with that key and sealed again under
 * the current one, after which the old key is removed from the configuration.
 */
public final class SealedBox {

    private static final int KEY_BYTES = 32;      // AES-256
    private static final int IV_BYTES = 12;       // the standard GCM nonce length
    private static final int TAG_BITS = 128;
    private static final Pattern KEY_ID = Pattern.compile("[a-z0-9]{1,16}");

    private final String prefix;
    private final Map<String, SecretKey> keys;
    private final String currentKeyId;
    private final SecureRandom random = new SecureRandom();

    /**
     * @param prefix       what kind of record this box seals, such as "pepper"
     * @param base64Keys   key id to 32 random bytes in Base64
     * @param currentKeyId the key every new record is sealed with
     */
    public SealedBox(String prefix, Map<String, String> base64Keys, String currentKeyId) {
        if (base64Keys == null || base64Keys.isEmpty()) {
            throw new IllegalStateException("no keys configured for " + prefix);
        }
        Map<String, SecretKey> loaded = new LinkedHashMap<>();
        base64Keys.forEach((id, value) -> {
            if (!KEY_ID.matcher(id).matches()) {
                throw new IllegalStateException(prefix + " key id must match " + KEY_ID + ": " + id);
            }
            byte[] raw = Base64.getDecoder().decode(value.trim());
            if (raw.length != KEY_BYTES) {
                throw new IllegalStateException(prefix + " key " + id + " must decode to 32 bytes");
            }
            loaded.put(id, new SecretKeySpec(raw, "AES"));
        });
        if (currentKeyId == null || !loaded.containsKey(currentKeyId)) {
            throw new IllegalStateException("current " + prefix + " key '" + currentKeyId + "' is not configured");
        }
        this.prefix = prefix;
        this.keys = Map.copyOf(loaded);
        this.currentKeyId = currentKeyId;
    }

    public String currentKeyId() {
        return currentKeyId;
    }

    public String seal(String plaintext, String associatedData) {
        try {
            byte[] iv = new byte[IV_BYTES];
            random.nextBytes(iv);                          // never reuse an IV under the same key
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keys.get(currentKeyId), new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(associatedData.getBytes(StandardCharsets.UTF_8));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] blob = new byte[IV_BYTES + ciphertext.length];
            System.arraycopy(iv, 0, blob, 0, IV_BYTES);
            System.arraycopy(ciphertext, 0, blob, IV_BYTES, ciphertext.length);
            return prefix + ":" + currentKeyId + ":" + Base64.getEncoder().encodeToString(blob);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM unavailable", e);
        }
    }

    /**
     * Decrypts a sealed record. Throws when the key is unknown, when the record belongs to another
     * row, or when a single bit of it was changed: the GCM tag checks all three.
     */
    public String open(String sealed, String associatedData) throws GeneralSecurityException {
        String[] parts = sealed.split(":", 3);
        if (parts.length != 3 || !prefix.equals(parts[0])) {
            throw new GeneralSecurityException("not a sealed " + prefix + " record");
        }
        SecretKey key = keys.get(parts[1]);
        if (key == null) {
            throw new GeneralSecurityException("unknown " + prefix + " key " + parts[1]);
        }
        byte[] blob;
        try {
            blob = Base64.getDecoder().decode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("malformed sealed record", e);
        }
        if (blob.length < IV_BYTES + TAG_BITS / 8) {
            throw new GeneralSecurityException("sealed record too short");
        }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, blob, 0, IV_BYTES));
        cipher.updateAAD(associatedData.getBytes(StandardCharsets.UTF_8));
        byte[] plain = cipher.doFinal(blob, IV_BYTES, blob.length - IV_BYTES);
        return new String(plain, StandardCharsets.UTF_8);
    }

    /** True when the record is sealed under the current key, so rotation can skip it. */
    public boolean isCurrent(String sealed) {
        return sealed.startsWith(prefix + ":" + currentKeyId + ":");
    }

    /** Re-encrypts a record under the current key: rotation without the user's password. */
    public String reseal(String sealed, String associatedData) throws GeneralSecurityException {
        return seal(open(sealed, associatedData), associatedData);
    }
}
