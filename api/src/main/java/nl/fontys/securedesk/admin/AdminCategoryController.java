package nl.fontys.securedesk.admin;

import jakarta.validation.Valid;
import nl.fontys.securedesk.auth.RequiresRecentAuthentication;
import nl.fontys.securedesk.ticket.CategoryService;
import nl.fontys.securedesk.ticket.TicketDtos;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/** UC-06: ticket categories. */
@RestController
@RequestMapping("/api/admin/categories")
public class AdminCategoryController {

    private final CategoryService categories;

    public AdminCategoryController(CategoryService categories) {
        this.categories = categories;
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public List<TicketDtos.CategoryView> all() {
        return categories.all();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('ADMIN')")
    @RequiresRecentAuthentication
    public TicketDtos.CategoryView create(@Valid @RequestBody TicketDtos.CategoryRequest body) {
        return categories.create(body);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @RequiresRecentAuthentication
    public TicketDtos.CategoryView update(@PathVariable Long id, @Valid @RequestBody TicketDtos.CategoryRequest body) {
        return categories.update(id, body);
    }
}
