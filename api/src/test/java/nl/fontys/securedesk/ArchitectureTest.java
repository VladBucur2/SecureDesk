package nl.fontys.securedesk;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import jakarta.persistence.Entity;
import nl.fontys.securedesk.auth.RequiresRecentAuthentication;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.repository.Repository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.methods;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noMethods;

/**
 * The rules that keep SC-03 from being bypassed by a new endpoint (BoK 5.2.3 B). The residual
 * weakness of that design is that the check is enforced by convention; these rules turn the
 * convention into a failing build.
 */
class ArchitectureTest {

    private static JavaClasses classes;

    @BeforeAll
    static void importClasses() {
        classes = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages("nl.fontys.securedesk");
    }

    @Test
    @DisplayName("a controller never calls a repository: every data access goes through a service")
    void controllersDoNotUseRepositories() {
        ArchRule rule = noClasses().that().areAnnotatedWith(RestController.class)
                .should().dependOnClassesThat().areAssignableTo(Repository.class)
                .because("a controller that reads a repository skips TicketAccessService, "
                        + "which is the shape of the mistake that bypasses object-level authorisation");
        rule.check(classes);
    }

    @Test
    @DisplayName("every endpoint carries its own @PreAuthorize, even the public ones")
    void everyEndpointIsAnnotated() {
        ArchRule rule = methods().that().areDeclaredInClassesThat().areAnnotatedWith(RestController.class)
                .and().arePublic()
                .and(com.tngtech.archunit.base.DescribedPredicate.describe("are request handlers",
                        method -> method.isAnnotatedWith(GetMapping.class) || method.isAnnotatedWith(PostMapping.class)
                                || method.isAnnotatedWith(PutMapping.class) || method.isAnnotatedWith(DeleteMapping.class)
                                || method.isAnnotatedWith(PatchMapping.class) || method.isAnnotatedWith(RequestMapping.class)))
                .should().beAnnotatedWith(PreAuthorize.class)
                .because("deny by default: a handler without its own check relies on a URL rule alone");
        rule.check(classes);
    }

    @Test
    @DisplayName("every state-changing administrative endpoint requires a recent authentication")
    void adminChangesNeedStepUp() {
        ArchRule rule = methods().that().areDeclaredInClassesThat().haveSimpleNameStartingWith("Admin")
                .and().areDeclaredInClassesThat().areAnnotatedWith(RestController.class)
                .and(com.tngtech.archunit.base.DescribedPredicate.describe("change state",
                        method -> method.isAnnotatedWith(PostMapping.class) || method.isAnnotatedWith(PutMapping.class)
                                || method.isAnnotatedWith(DeleteMapping.class) || method.isAnnotatedWith(PatchMapping.class)))
                .should().beAnnotatedWith(RequiresRecentAuthentication.class)
                .because("UC-05: administrative endpoints require the administrator role plus a recent authentication");
        rule.check(classes);
    }

    @Test
    @DisplayName("controllers return DTOs, never entities")
    void noEntitiesOverTheWire() {
        ArchRule rule = noMethods().that().areDeclaredInClassesThat().areAnnotatedWith(RestController.class)
                .and().arePublic()
                .should().haveRawReturnType(com.tngtech.archunit.base.DescribedPredicate.describe("an entity",
                        type -> type.isAnnotatedWith(Entity.class)))
                .because("an entity carries fields such as the password record that no client may see");
        rule.check(classes);
    }

    @Test
    @DisplayName("only the audit package writes audit events")
    void auditWriterIsPrivateToItsPackage() {
        ArchRule rule = noClasses().that().resideOutsideOfPackage("..audit..")
                .should().dependOnClassesThat().haveSimpleName("AuditWriter");
        rule.check(classes);
    }
}
