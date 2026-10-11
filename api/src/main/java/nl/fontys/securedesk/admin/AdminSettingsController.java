package nl.fontys.securedesk.admin;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import nl.fontys.securedesk.auth.RequiresRecentAuthentication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** UC-06: the retention period for closed tickets. */
@RestController
@RequestMapping("/api/admin/settings/retention")
public class AdminSettingsController {

    public record RetentionRequest(@NotNull Integer months) {
    }

    private final RetentionService retention;

    public AdminSettingsController(RetentionService retention) {
        this.retention = retention;
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public RetentionService.Retention get() {
        return retention.current();
    }

    @PutMapping
    @PreAuthorize("hasRole('ADMIN')")
    @RequiresRecentAuthentication
    public RetentionService.Retention change(@Valid @RequestBody RetentionRequest body) {
        return retention.change(body.months());
    }

    @PostMapping("/run")
    @PreAuthorize("hasRole('ADMIN')")
    @RequiresRecentAuthentication
    public Map<String, Integer> runNow() {
        return Map.of("deleted", retention.purge(false));
    }
}
