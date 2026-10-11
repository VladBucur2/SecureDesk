package nl.fontys.securedesk.migrate;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.output.MigrateResult;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * The `migrate` service: applies the schema and the grants, then exits. It runs from the same
 * image as the API but without Spring and with the migrator account, which has DDL rights on the
 * SecureDesk schema. The API container never receives that account's password, so the running
 * application cannot alter tables or its own grants (SC-06).
 *
 * <p>Configuration from the environment: MIGRATE_DB_URL, MIGRATE_DB_USER, MIGRATE_DB_PASSWORD_FILE
 * and MIGRATE_APP_DB_USER (the account the grants are for).
 */
public final class MigrateMain {

    private MigrateMain() {
    }

    public static void main(String[] args) throws IOException {
        ((Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME)).setLevel(Level.INFO);

        String url = required("MIGRATE_DB_URL");
        String user = required("MIGRATE_DB_USER");
        String password = Files.readString(Path.of(required("MIGRATE_DB_PASSWORD_FILE"))).strip();
        String appUser = System.getenv().getOrDefault("MIGRATE_APP_DB_USER", "securedesk_app");

        Flyway flyway = Flyway.configure()
                .dataSource(url, user, password)
                .locations("classpath:db/migration", "classpath:db/mysql")
                .placeholders(Map.of("app_user", appUser))
                .connectRetries(30)
                .load();
        MigrateResult result = flyway.migrate();
        System.out.println("migrate: " + result.migrationsExecuted + " migration(s) applied, schema version "
                + result.targetSchemaVersion);
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is not set");
        }
        return value;
    }
}
