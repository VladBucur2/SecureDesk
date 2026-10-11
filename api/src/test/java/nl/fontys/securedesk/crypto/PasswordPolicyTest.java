package nl.fontys.securedesk.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PasswordPolicyTest {

    private static final PasswordPolicy POLICY = PasswordPolicy.withBundledBlocklist();

    @Test
    @DisplayName("enforces 15 to 128 characters")
    void enforcesLength() {
        assertThrows(PasswordPolicy.Rejected.class, () -> POLICY.accept("fourteen chars"));
        assertEquals("fifteen chars!!", POLICY.accept("fifteen chars!!"));
        assertEquals(128, PasswordPolicy.length(POLICY.accept("b".repeat(128))));
        assertThrows(PasswordPolicy.Rejected.class, () -> POLICY.accept("b".repeat(129)));
    }

    @Test
    @DisplayName("counts code points, not Java chars: 15 emoji are 15 characters")
    void countsCodePoints() {
        String emoji = "🙂".repeat(15);    // U+1F642, two Java chars each
        assertEquals(30, emoji.length());
        assertEquals(15, PasswordPolicy.length(POLICY.accept(emoji)));
    }

    @Test
    @DisplayName("rejects long but common passwords, regardless of case")
    void rejectsCommonPasswords() {
        assertThrows(PasswordPolicy.Rejected.class, () -> POLICY.accept("manchesterunited"));
        assertThrows(PasswordPolicy.Rejected.class, () -> POLICY.accept("ManchesterUnited"));
        assertThrows(PasswordPolicy.Rejected.class, () -> POLICY.accept("1q2w3e4r5t6y7u8i9o0p"));
    }

    @Test
    @DisplayName("accepts spaces and non-ASCII characters, and returns the NFC form")
    void normalisesToNfc() {
        String decomposed = "café au lait at the station";
        assertEquals("café au lait at the station", POLICY.accept(decomposed));
    }

    @Test
    @DisplayName("rejects the name of the service and the user's own username or name")
    void rejectsContextSpecificWords() {
        assertThrows(PasswordPolicy.Rejected.class, () -> POLICY.accept("my SecureDesk password 2026"));
        assertThrows(PasswordPolicy.Rejected.class,
                () -> POLICY.accept("hello alice.jansen it is me", "alice.jansen", "Alice Jansen"));
        assertThrows(PasswordPolicy.Rejected.class,
                () -> POLICY.accept("ALICE JANSEN forever and ever", "alice.jansen", "Alice Jansen"));
        // too short to count as context: a two-letter username does not block every password with "bo"
        assertEquals("a boat on the quiet river", POLICY.accept("a boat on the quiet river", "bo"));
    }
}
