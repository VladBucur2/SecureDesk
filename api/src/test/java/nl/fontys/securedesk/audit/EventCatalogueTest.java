package nl.fontys.securedesk.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * docs/event-catalogue.md is what the blue team writes its rules against (BoK 5.3.5), so it
 * must name every event the code can write, and no event the code cannot. The image build has
 * no docs directory, so there the test is skipped; in the repository and in CI it runs.
 */
class EventCatalogueTest {

    private static final Path CATALOGUE = Path.of("..", "docs", "event-catalogue.md");
    /** An event row: the first cell is the type in backticks. */
    private static final Pattern ROW = Pattern.compile("(?m)^\\| `([A-Z_]+)` \\|");

    @Test
    @DisplayName("the event catalogue lists exactly the event types of the code")
    void catalogueMatchesTheCode() throws IOException {
        assumeTrue(Files.exists(CATALOGUE), "docs/event-catalogue.md not present (image build)");
        String text = Files.readString(CATALOGUE);

        Set<String> documented = new TreeSet<>();
        Matcher row = ROW.matcher(text);
        while (row.find()) {
            documented.add(row.group(1));
        }
        Set<String> inCode = new TreeSet<>(Arrays.stream(AuditType.values()).map(Enum::name).toList());

        assertThat(documented).as("event types in docs/event-catalogue.md").isEqualTo(inCode);
    }
}
