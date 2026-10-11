package nl.fontys.securedesk.crypto;

import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;
import java.util.UUID;

/**
 * Column encryption of the TOTP secrets (SR-05), with its own keyring. The mfa-poc encrypted the
 * secret without associated data; here the user id is bound to it, so a secret copied from one
 * row into another, or one an attacker enrolled for himself and wrote into a victim's row, does
 * not open.
 */
@Component
public class TotpSecretCipher {

    private final SealedBox box;

    public TotpSecretCipher(CryptoProperties properties) {
        CryptoProperties.KeyRing ring = properties.totp();
        if (ring == null) {
            throw new IllegalStateException("securedesk.crypto.totp is not configured");
        }
        this.box = new SealedBox("totp", ring.keys(), ring.current());
    }

    public String seal(UUID userId, String base32Secret) {
        return box.seal(base32Secret, context(userId));
    }

    public String open(UUID userId, String sealed) throws GeneralSecurityException {
        return box.open(sealed, context(userId));
    }

    public String reseal(UUID userId, String sealed) throws GeneralSecurityException {
        return box.reseal(sealed, context(userId));
    }

    public boolean isCurrent(String sealed) {
        return box.isCurrent(sealed);
    }

    private static String context(UUID userId) {
        return "totp:" + userId;
    }
}
