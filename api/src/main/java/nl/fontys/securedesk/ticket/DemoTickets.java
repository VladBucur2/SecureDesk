package nl.fontys.securedesk.ticket;

import nl.fontys.securedesk.user.AppUser;
import nl.fontys.securedesk.user.AppUserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * A few tickets for the demonstration accounts, so the queue, the internal notes and the object
 * level checks can be shown (and attacked) without typing them first. Only with
 * {@code securedesk.demo.enabled}, and only once.
 */
@Component
@Order(2)
class DemoTickets implements ApplicationRunner {

    private final AppUserRepository users;
    private final TicketRepository tickets;
    private final TicketCommentRepository comments;
    private final CategoryRepository categories;
    private final Clock clock;
    private final boolean enabled;

    DemoTickets(AppUserRepository users, TicketRepository tickets, TicketCommentRepository comments,
                CategoryRepository categories, Clock clock, @Value("${securedesk.demo.enabled:false}") boolean enabled) {
        this.users = users;
        this.tickets = tickets;
        this.comments = comments;
        this.categories = categories;
        this.clock = clock;
        this.enabled = enabled;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        Optional<AppUser> alice = users.findByUsername("alice");
        Optional<AppUser> bob = users.findByUsername("bob");
        Optional<AppUser> carol = users.findByUsername("carol");
        if (!enabled || alice.isEmpty() || bob.isEmpty() || carol.isEmpty() || tickets.count() > 0) {
            return;
        }
        List<Category> active = categories.findByActiveTrueOrderByNameAsc();
        Long hardware = byName(active, "Hardware");
        Long access = byName(active, "Access request");
        Long software = byName(active, "Software");
        Instant now = clock.instant();

        Ticket laptop = new Ticket(alice.get().getId(), hardware, "My laptop won't boot",
                "Since this morning the laptop shows a black screen after the logo. I tried a restart.",
                now.minus(Duration.ofHours(5)));
        laptop.changeStatus(TicketStatus.IN_PROGRESS, now);
        laptop.setAssigneeId(carol.get().getId());
        laptop.setPriority(TicketPriority.HIGH);
        tickets.save(laptop);
        comments.save(new TicketComment(laptop.getId(), carol.get().getId(),
                "I will come by at two to have a look.", false, now.minus(Duration.ofHours(4))));
        comments.save(new TicketComment(laptop.getId(), carol.get().getId(),
                "Internal: disk shows SMART errors; order a replacement before telling the user.", true,
                now.minus(Duration.ofHours(3))));

        tickets.save(new Ticket(alice.get().getId(), access, "I need access to the ERP system",
                "I joined the purchasing team and need read access to purchase orders in the ERP.",
                now.minus(Duration.ofHours(2))));

        tickets.save(new Ticket(bob.get().getId(), software, "Excel crashes when opening large files",
                "Files over 50 MB make Excel close without a message.", now.minus(Duration.ofHours(1))));
    }

    private static Long byName(List<Category> categories, String name) {
        return categories.stream().filter(c -> c.getName().equals(name)).findFirst()
                .orElse(categories.get(0)).getId();
    }
}
