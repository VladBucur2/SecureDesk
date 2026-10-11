package nl.fontys.securedesk.user;

import java.security.SecureRandom;

/**
 * Temporary passwords issued by an administrator: four groups of five characters from an
 * alphabet without look-alikes, about 99 bits, shown once and changed at the next sign-in.
 */
public final class TemporaryPasswords {

    private static final String ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789";
    private static final SecureRandom RANDOM = new SecureRandom();

    private TemporaryPasswords() {
    }

    public static String generate() {
        StringBuilder out = new StringBuilder(23);
        for (int group = 0; group < 4; group++) {
            if (group > 0) {
                out.append('-');
            }
            for (int i = 0; i < 5; i++) {
                out.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
            }
        }
        return out.toString();
    }
}
