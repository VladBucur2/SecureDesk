package nl.fontys.securedesk.user;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import nl.fontys.securedesk.auth.RequiresRecentAuthentication;
import nl.fontys.securedesk.common.PageResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/** UC-05. Every change requires the administrator role and a recent authentication. */
@RestController
@RequestMapping("/api/admin/users")
public class AdminUserController {

    private final UserAdminService service;

    public AdminUserController(UserAdminService service) {
        this.service = service;
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public PageResponse<UserDtos.UserView> list(@RequestParam(defaultValue = "0") @Min(0) int page,
                                                @RequestParam(defaultValue = "20") @Min(1) @Max(PageResponse.MAX_SIZE) int size) {
        return PageResponse.of(service.list(page, size), UserDtos.UserView::of);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('ADMIN')")
    @RequiresRecentAuthentication
    public UserDtos.TemporaryPasswordView create(@Valid @RequestBody UserDtos.CreateUserRequest body) {
        UserAdminService.Created created = service.create(body);
        return new UserDtos.TemporaryPasswordView(UserDtos.UserView.of(created.user()), created.temporaryPassword());
    }

    @PutMapping("/{id}/role")
    @PreAuthorize("hasRole('ADMIN')")
    @RequiresRecentAuthentication
    public UserDtos.UserView changeRole(@PathVariable UUID id, @Valid @RequestBody UserDtos.RoleRequest body) {
        return UserDtos.UserView.of(service.changeRole(id, body.role()));
    }

    @PutMapping("/{id}/enabled")
    @PreAuthorize("hasRole('ADMIN')")
    @RequiresRecentAuthentication
    public UserDtos.UserView setEnabled(@PathVariable UUID id, @Valid @RequestBody UserDtos.EnabledRequest body) {
        return UserDtos.UserView.of(service.setEnabled(id, body.enabled()));
    }

    @PostMapping("/{id}/mfa-reset")
    @PreAuthorize("hasRole('ADMIN')")
    @RequiresRecentAuthentication
    public UserDtos.UserView resetMfa(@PathVariable UUID id) {
        return UserDtos.UserView.of(service.resetMfa(id));
    }

    @PutMapping("/{id}/mfa-required")
    @PreAuthorize("hasRole('ADMIN')")
    @RequiresRecentAuthentication
    public UserDtos.UserView setMfaRequired(@PathVariable UUID id, @Valid @RequestBody UserDtos.MfaRequiredRequest body) {
        return UserDtos.UserView.of(service.setMfaRequired(id, body.required()));
    }

    @PostMapping("/{id}/temporary-password")
    @PreAuthorize("hasRole('ADMIN')")
    @RequiresRecentAuthentication
    public UserDtos.TemporaryPasswordView temporaryPassword(@PathVariable UUID id) {
        UserAdminService.Created created = service.issueTemporaryPassword(id);
        return new UserDtos.TemporaryPasswordView(UserDtos.UserView.of(created.user()), created.temporaryPassword());
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @RequiresRecentAuthentication
    public UserDtos.UserView erase(@PathVariable UUID id) {
        return UserDtos.UserView.of(service.erase(id));
    }
}
