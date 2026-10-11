package nl.fontys.securedesk.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import static nl.fontys.securedesk.crypto.PasswordHasher.Outcome.FAILED;
import static nl.fontys.securedesk.crypto.PasswordHasher.Outcome.OK;
import static nl.fontys.securedesk.crypto.PasswordHasher.Outcome.OK_REHASHED;
import static nl.fontys.securedesk.crypto.PasswordHasher.Outcome.TAMPERED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The behaviour of the PoC's {@code PasswordStoreTest}, against the class SecureDesk uses. The
 * user table is gone from this level: a "row" here is the sealed string the entity would hold.
 */
class PasswordHasherTest {

    private static final PasswordPolicy POLICY = PasswordPolicy.withBundledBlocklist();
    private static final String PASSWORD = "lantern orbit mosaic gravel";

    private final CryptoProperties properties = TestKeys.properties();
    private final Pepper pepper = new Pepper(properties);
    private final PasswordHasher hasher = new PasswordHasher(pepper, properties);

    private final UUID dave = UUID.randomUUID();
    private final UUID erin = UUID.randomUUID();

    @Test
    @DisplayName("accepts the right password and rejects a wrong one")
    void verifies() {
        String record = hasher.newPasswordRecord(dave, POLICY.accept(PASSWORD));

        assertEquals(OK, hasher.verifyPassword(dave, record, PASSWORD).outcome());
        assertEquals(FAILED, hasher.verifyPassword(dave, record, PASSWORD + "!").outcome());
    }

    @Test
    @DisplayName("stores only a sealed record, with a fresh salt every time")
    void storesSealedSaltedHashOnly() throws GeneralSecurityException {
        String daveRecord = hasher.newPasswordRecord(dave, PASSWORD);
        String erinRecord = hasher.newPasswordRecord(erin, PASSWORD);

        assertTrue(daveRecord.startsWith("pepper:k1:"));
        assertFalse(daveRecord.contains("lantern"));
        assertFalse(daveRecord.contains("argon2id"));
        StoredHash daveHash = StoredHash.parse(pepper.openPassword(dave, daveRecord));
        StoredHash erinHash = StoredHash.parse(pepper.openPassword(erin, erinRecord));
        assertNotEquals(daveHash.format().split("\\$")[4], erinHash.format().split("\\$")[4], "salts must differ");
        assertEquals(PasswordPolicy.SALT_BYTES, daveHash.salt().length);
        assertEquals(PasswordPolicy.CURRENT, daveHash.params());
    }

    @Test
    @DisplayName("upgrades a hash made with older parameters at the next login")
    void rehashesOutdatedParameters() throws GeneralSecurityException {
        String old = pepper.sealPassword(erin,
                hasher.newHash(PASSWORD, new Argon2id.Params(4_096, 3, 1)).format());

        PasswordHasher.Check first = hasher.verifyPassword(erin, old, PASSWORD);
        assertEquals(OK_REHASHED, first.outcome());
        assertNotNull(first.upgradedRecord());
        assertEquals(PasswordPolicy.CURRENT, StoredHash.parse(pepper.openPassword(erin, first.upgradedRecord())).params());
        assertEquals(OK, hasher.verifyPassword(erin, first.upgradedRecord(), PASSWORD).outcome());
    }

    @Test
    @DisplayName("treats differently encoded but identical Unicode text as the same password")
    void normalisesBeforeHashing() {
        String record = hasher.newPasswordRecord(dave, POLICY.accept("café au lait at the station"));

        assertEquals(OK, hasher.verifyPassword(dave, record, "café au lait at the station").outcome());
    }

    @Test
    @DisplayName("checks every character of a long passphrase: no truncation")
    void doesNotTruncate() {
        String phrase = "w".repeat(99) + "x";
        String record = hasher.newPasswordRecord(erin, POLICY.accept(phrase));

        assertEquals(OK, hasher.verifyPassword(erin, record, phrase).outcome());
        assertEquals(FAILED, hasher.verifyPassword(erin, record, "w".repeat(99) + "y").outcome());
    }

    @Test
    @DisplayName("refuses an over-long password at login without hashing it")
    void refusesOverlongInput() {
        String record = hasher.newPasswordRecord(dave, PASSWORD);

        assertEquals(FAILED, hasher.verifyPassword(dave, record, "z".repeat(100_000)).outcome());
    }

    @Test
    @DisplayName("a copied, planted or altered record is detected")
    void detectsTableTampering() {
        String aliceRow = hasher.newPasswordRecord(dave, PASSWORD);
        String malloryRow = hasher.newPasswordRecord(erin, "mallory chose this one himself");

        // Mallory copies his own row over Alice's
        assertEquals(TAMPERED, hasher.verifyPassword(dave, malloryRow, "mallory chose this one himself").outcome());

        // ... or writes a valid, unsealed Argon2id record of his own password
        String planted = hasher.newHash("mallory chose this one himself", PasswordPolicy.CURRENT).format();
        assertEquals(TAMPERED, hasher.verifyPassword(dave, planted, "mallory chose this one himself").outcome());

        // ... or flips one character of Alice's record
        char last = aliceRow.charAt(aliceRow.length() - 1);
        String altered = aliceRow.substring(0, aliceRow.length() - 1) + (last == 'A' ? 'B' : 'A');
        assertEquals(TAMPERED, hasher.verifyPassword(dave, altered, PASSWORD).outcome());
    }

    @Test
    @DisplayName("rotates the pepper key without any password, and logins keep working")
    void rotatesPepper() throws GeneralSecurityException {
        Map<String, String> keys = new LinkedHashMap<>(properties.pepper().keys());
        String before = hasher.newPasswordRecord(dave, PASSWORD);

        // step 1: k2 added and made current; k1 still present for reading
        keys.put("k2", TestKeys.randomKey());
        CryptoProperties both = new CryptoProperties(new CryptoProperties.KeyRing("k2", keys), properties.totp(), 2);
        Pepper rotating = new Pepper(both);
        assertFalse(rotating.isCurrent(before));
        String after = rotating.resealPassword(dave, before);
        assertTrue(after.startsWith("pepper:k2:"));

        // step 2: k1 removed from the configuration
        keys.remove("k1");
        CryptoProperties onlyK2 = new CryptoProperties(new CryptoProperties.KeyRing("k2", keys), properties.totp(), 2);
        PasswordHasher afterRotation = new PasswordHasher(new Pepper(onlyK2), onlyK2);
        assertEquals(OK, afterRotation.verifyPassword(dave, after, PASSWORD).outcome());
        assertEquals(TAMPERED, afterRotation.verifyPassword(dave, before, PASSWORD).outcome(),
                "a backup sealed with k1 no longer opens once k1 is gone");
    }

    @Test
    @DisplayName("an erased account has no record, fails, and still costs a hash")
    void missingRecordFails() {
        assertEquals(FAILED, hasher.verifyPassword(dave, null, PASSWORD).outcome());
    }

    @Test
    @DisplayName("recovery codes are sealed to their own row and cannot be moved")
    void recoveryCodesAreBoundToTheirRow() {
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();
        String record = hasher.newRecoveryCodeRecord(first, "ABCD2345");

        assertEquals(OK, hasher.verifyRecoveryCode(first, record, "ABCD2345"));
        assertEquals(FAILED, hasher.verifyRecoveryCode(first, record, "ABCD2346"));
        assertEquals(TAMPERED, hasher.verifyRecoveryCode(second, record, "ABCD2345"));
    }
}
