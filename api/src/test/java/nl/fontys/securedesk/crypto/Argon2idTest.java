package nl.fontys.securedesk.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Known-answer tests: the hashing is checked against published or independently computed values,
 * so its correctness is verified rather than assumed.
 */
class Argon2idTest {

    @Test
    @DisplayName("matches the Argon2id test vector of RFC 9106, section 5.3")
    void matchesRfc9106TestVector() {
        byte[] password = filled(32, 0x01);
        byte[] salt = filled(16, 0x02);
        byte[] secret = filled(8, 0x03);
        byte[] associatedData = filled(12, 0x04);
        Argon2id.Params params = new Argon2id.Params(32, 3, 4);   // 32 KiB, 3 passes, 4 lanes

        byte[] tag = Argon2id.compute(password, salt, params, 32, secret, associatedData);

        assertEquals("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
                HexFormat.of().formatHex(tag));
    }

    @Test
    @DisplayName("agrees with the Argon2 reference implementation at the parameters the PoC uses")
    void matchesReferenceImplementation() {
        // Produced with argon2-cffi 25.1.0, which wraps the reference C implementation:
        // hash_secret(b"correct horse battery staple", b"saltsaltsaltsalt",
        //             time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, type=Type.ID)
        String reference = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA"
                + "$QKHrg5tayLGcN+Y0HVPNaBqykOVLUxlMkZycXE1uWRM";

        StoredHash stored = StoredHash.parse(reference);
        byte[] mine = Argon2id.hash("correct horse battery staple".getBytes(StandardCharsets.UTF_8),
                stored.salt(), stored.params(), stored.hash().length);

        assertArrayEquals(stored.hash(), mine);
        assertEquals(reference, new StoredHash(stored.params(), stored.salt(), mine).format(),
                "the PHC string must be written exactly as the reference writes it");
    }

    @Test
    @DisplayName("a different salt gives an unrelated hash for the same password")
    void saltChangesTheHash() {
        byte[] password = "lantern orbit mosaic gravel".getBytes(StandardCharsets.UTF_8);
        Argon2id.Params params = PasswordPolicy.CURRENT;

        byte[] first = Argon2id.hash(password, filled(16, 0x01), params, 32);
        byte[] again = Argon2id.hash(password, filled(16, 0x01), params, 32);
        byte[] otherSalt = Argon2id.hash(password, filled(16, 0x02), params, 32);

        assertArrayEquals(first, again, "same inputs, same hash: verification depends on it");
        assertFalse(Arrays.equals(first, otherSalt));
    }

    private static byte[] filled(int length, int value) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }
}
