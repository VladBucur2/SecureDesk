package nl.fontys.securedesk.crypto;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * The current storage parameters, and the rules a new password must meet before it is stored
 * (from the password-storage PoC, BoK 6.3).
 *
 * <p>SecureDesk keeps the PoC's minimum of 15 characters rather than NIST's 8 for multi-factor
 * use, because requesters can be without a second factor (BoK 6.3.7). It adds one rule the PoC
 * left out: NIST SP 800-63B-4 also lists context-specific words such as the name of the service
 * and the username, so a password containing either is refused.
 */
public final class PasswordPolicy {

    /** OWASP minimum for Argon2id: 19 MiB of memory, 2 passes, 1 lane. */
    public static final Argon2id.Params CURRENT = new Argon2id.Params(19_456, 2, 1);

    /** RFC 9106 recommends 16 bytes of salt for password hashing. */
    public static final int SALT_BYTES = 16;

    /** Length of the stored hash: 256 bits. */
    public static final int HASH_BYTES = 32;

    /** NIST SP 800-63B-4: at least 15 characters when the password is the only factor. */
    public static final int MIN_LENGTH = 15;

    /** NIST SP 800-63B-4: allow at least 64; the upper bound only stops absurd input. */
    public static final int MAX_LENGTH = 128;

    /** Context-specific words shorter than this are not checked: "bo" would reject too much. */
    private static final int MIN_CONTEXT_WORD = 4;

    private static final List<String> SERVICE_WORDS = List.of("securedesk", "secure desk");

    private final Set<String> blocklist;

    public PasswordPolicy(Set<String> blocklist) {
        this.blocklist = Set.copyOf(blocklist);
    }

    /** The policy with the 100,000 most common breached passwords as its blocklist. */
    public static PasswordPolicy withBundledBlocklist() {
        return new PasswordPolicy(loadCommonPasswords());
    }

    /**
     * Checks a new password. Returns it NFC-normalised, ready for hashing, or throws
     * {@link Rejected} with the reason. Deliberately no composition rules (no "one digit, one
     * capital"): NIST forbids them, because they push people towards predictable patterns.
     *
     * @param contextWords words specific to this user, such as the username and display name
     */
    public String accept(String password, String... contextWords) {
        String normalised = normalise(password);
        int length = length(normalised);
        if (length < MIN_LENGTH) {
            throw new Rejected("shorter than " + MIN_LENGTH + " characters");
        }
        if (length > MAX_LENGTH) {
            throw new Rejected("longer than " + MAX_LENGTH + " characters");
        }
        String lower = normalised.toLowerCase(Locale.ROOT);
        if (blocklist.contains(lower)) {
            throw new Rejected("on the list of commonly used passwords");
        }
        for (String word : SERVICE_WORDS) {
            if (lower.contains(word)) {
                throw new Rejected("contains the name of the service");
            }
        }
        for (String word : contextWords) {
            if (word != null && length(word) >= MIN_CONTEXT_WORD
                    && lower.contains(normalise(word).toLowerCase(Locale.ROOT))) {
                throw new Rejected("contains your username or name");
            }
        }
        return normalised;
    }

    /**
     * The same character can be typed as different code points ("é" as one code point, or "e"
     * plus a combining accent). Normalising to NFC before hashing makes both produce the same hash.
     */
    public static String normalise(String password) {
        return Normalizer.normalize(password, Normalizer.Form.NFC);
    }

    /** Length in code points, as NIST counts it: an emoji or an "é" is one character. */
    public static int length(String password) {
        return password.codePointCount(0, password.length());
    }

    /** The bundled list, one password per line, most common first. */
    public static List<String> commonPasswordsInOrder() {
        try (InputStream in = PasswordPolicy.class.getResourceAsStream("/common-passwords.txt")) {
            if (in == null) {
                throw new IllegalStateException("common-passwords.txt is missing from the jar");
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            return reader.lines().filter(line -> !line.isEmpty()).toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Set<String> loadCommonPasswords() {
        Set<String> set = new HashSet<>();
        for (String line : commonPasswordsInOrder()) {
            set.add(normalise(line).toLowerCase(Locale.ROOT));
        }
        return set;
    }

    /** Thrown when a new password does not meet the policy. The reason is safe to show. */
    public static final class Rejected extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public Rejected(String reason) {
            super(reason);
        }
    }
}
