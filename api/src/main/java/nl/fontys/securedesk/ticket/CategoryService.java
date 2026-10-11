package nl.fontys.securedesk.ticket;

import nl.fontys.securedesk.audit.AuditLog;
import nl.fontys.securedesk.audit.AuditType;
import nl.fontys.securedesk.common.ApiException;
import nl.fontys.securedesk.common.TextSanitizer;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/** UC-06: categories are added, renamed and deactivated, never deleted, so old tickets keep theirs. */
@Service
public class CategoryService {

    private final CategoryRepository categories;
    private final AuditLog audit;

    public CategoryService(CategoryRepository categories, AuditLog audit) {
        this.categories = categories;
        this.audit = audit;
    }

    public List<TicketDtos.CategoryView> active() {
        return categories.findByActiveTrueOrderByNameAsc().stream().map(TicketDtos.CategoryView::of).toList();
    }

    public List<TicketDtos.CategoryView> all() {
        return categories.findAllByOrderByNameAsc().stream().map(TicketDtos.CategoryView::of).toList();
    }

    @Transactional
    public TicketDtos.CategoryView create(TicketDtos.CategoryRequest request) {
        String name = validName(request.name());
        if (categories.existsByNameIgnoreCase(name)) {
            throw ApiException.conflict("category_exists", "A category with that name exists.");
        }
        Category category = categories.save(new Category(name));
        audit.event(AuditType.CATEGORY_CREATED).target("category", category.getId()).detail("name", name).write();
        return TicketDtos.CategoryView.of(category);
    }

    @Transactional
    public TicketDtos.CategoryView update(Long id, TicketDtos.CategoryRequest request) {
        Category category = categories.findById(id).orElseThrow(ApiException::notFound);
        String name = validName(request.name());
        if (!name.equalsIgnoreCase(category.getName()) && categories.existsByNameIgnoreCase(name)) {
            throw ApiException.conflict("category_exists", "A category with that name exists.");
        }
        String oldName = category.getName();
        category.setName(name);
        if (request.active() != null) {
            category.setActive(request.active());
        }
        audit.event(AuditType.CATEGORY_UPDATED).target("category", category.getId())
                .detail("old_name", oldName).detail("name", name).detail("active", category.isActive()).write();
        return TicketDtos.CategoryView.of(categories.save(category));
    }

    private static String validName(String raw) {
        String name = TextSanitizer.cleanLine(raw);
        if (name == null || name.isEmpty() || name.length() > 60) {
            throw ApiException.badRequest("validation_failed", "A category name has 1 to 60 characters.");
        }
        return name;
    }
}
