package nl.fontys.securedesk.ticket;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/** The active categories, for the ticket form and the queue filter. */
@RestController
public class CategoryController {

    private final CategoryService categories;

    public CategoryController(CategoryService categories) {
        this.categories = categories;
    }

    @GetMapping("/api/categories")
    @PreAuthorize("isAuthenticated()")
    public List<TicketDtos.CategoryView> active() {
        return categories.active();
    }
}
