package nl.fontys.securedesk.crypto;

import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;
import java.util.UUID;

/**
 * The pepper of SC-02: every stored Argon2id record is encrypted with a key that is not in the
 * database. The associated data is the immutable id of the row, never the username, so a rename
 * does not break the record (BoK 6.3.7). Recovery codes are "hashed like passwords" and get the
 * same treatment; without it, an attacker with write access to the table could insert a recovery
 * code of his own and walk past the second factor.
 */
@Component
public class Pepper {

    private final SealedBox box;

    public Pepper(CryptoProperties properties) {
        CryptoProperties.KeyRing ring = properties.pepper();
        if (ring == null) {
            throw new IllegalStateException("securedesk.crypto.pepper is not configured");
        }
        this.box = new SealedBox("pepper", ring.keys(), ring.current());
    }

    public String sealPassword(UUID userId, String phcRecord) {
        return box.seal(phcRecord, passwordContext(userId));
    }

    public String openPassword(UUID userId, String sealed) throws GeneralSecurityException {
        return box.open(sealed, passwordContext(userId));
    }

    public String resealPassword(UUID userId, String sealed) throws GeneralSecurityException {
        return box.reseal(sealed, passwordContext(userId));
    }

    public String sealRecoveryCode(UUID codeId, String phcRecord) {
        return box.seal(phcRecord, recoveryContext(codeId));
    }

    public String openRecoveryCode(UUID codeId, String sealed) throws GeneralSecurityException {
        return box.open(sealed, recoveryContext(codeId));
    }

    public String resealRecoveryCode(UUID codeId, String sealed) throws GeneralSecurityException {
        return box.reseal(sealed, recoveryContext(codeId));
    }

    public boolean isCurrent(String sealed) {
        return box.isCurrent(sealed);
    }

    public String currentKeyId() {
        return box.currentKeyId();
    }

    private static String passwordContext(UUID userId) {
        return "password:" + userId;
    }

    private static String recoveryContext(UUID codeId) {
        return "recovery:" + codeId;
    }
}
