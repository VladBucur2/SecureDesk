package nl.fontys.securedesk.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class StoredHashTest {

    private static final String RECORD = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA"
            + "$QKHrg5tayLGcN+Y0HVPNaBqykOVLUxlMkZycXE1uWRM";

    @Test
    @DisplayName("reads the cost parameters, salt and hash, and writes them back unchanged")
    void roundTrips() {
        StoredHash stored = StoredHash.parse(RECORD);

        assertEquals(new Argon2id.Params(19_456, 2, 1), stored.params());
        assertEquals(16, stored.salt().length);
        assertEquals(32, stored.hash().length);
        assertEquals(RECORD, stored.format());
    }

    @Test
    @DisplayName("refuses other algorithms, other versions and incomplete parameters")
    void rejectsOtherFormats() {
        assertThrows(IllegalArgumentException.class,
                () -> StoredHash.parse(RECORD.replace("argon2id", "argon2i")));
        assertThrows(IllegalArgumentException.class,
                () -> StoredHash.parse(RECORD.replace("v=19", "v=16")));
        assertThrows(IllegalArgumentException.class,
                () -> StoredHash.parse(RECORD.replace(",p=1", "")));
        assertThrows(IllegalArgumentException.class,
                () -> StoredHash.parse("5f4dcc3b5aa765d61d8327deb882cf99"));   // an unsalted MD5
    }

    @Test
    @DisplayName("refuses cost parameters that would turn one login into a denial of service")
    void rejectsAbsurdCost() {
        assertThrows(IllegalArgumentException.class,
                () -> StoredHash.parse(RECORD.replace("m=19456", "m=2147483647")));
        assertThrows(IllegalArgumentException.class,
                () -> StoredHash.parse(RECORD.replace("t=2", "t=100000")));
        assertThrows(IllegalArgumentException.class,
                () -> StoredHash.parse(RECORD.replace("p=1", "p=0")));
    }
}
