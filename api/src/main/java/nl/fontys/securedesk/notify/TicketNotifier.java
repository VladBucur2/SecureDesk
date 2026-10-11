package nl.fontys.securedesk.notify;

import nl.fontys.securedesk.audit.AuditLog;
import nl.fontys.securedesk.audit.AuditType;
import nl.fontys.securedesk.audit.Outcome;
import nl.fontys.securedesk.user.AppUser;
import nl.fontys.securedesk.user.AppUserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

/**
 * UC-08: a mail to the requester when their ticket changes. Mail leaves the trust boundary to the
 * customer's SMTP relay, so it carries the ticket reference and a link and nothing else: no
 * description, no comment, no internal note (MU-13). The link only resolves after sign-in. The
 * address comes from the user record, never from a request parameter, so a notification cannot
 * be redirected.
 */
@Service
public class TicketNotifier {

    private static final Logger LOG = LoggerFactory.getLogger(TicketNotifier.class);

    private final AppUserRepository users;
    private final ObjectProvider<JavaMailSender> mailSender;
    private final AuditLog audit;
    private final boolean enabled;
    private final String from;
    private final String baseUrl;

    public TicketNotifier(AppUserRepository users, ObjectProvider<JavaMailSender> mailSender, AuditLog audit,
                          @Value("${securedesk.mail.enabled:false}") boolean enabled,
                          @Value("${securedesk.mail.from:securedesk@localhost}") String from,
                          @Value("${securedesk.base-url}") String baseUrl) {
        this.users = users;
        this.mailSender = mailSender;
        this.audit = audit;
        this.enabled = enabled;
        this.from = from;
        this.baseUrl = baseUrl;
    }

    @Async
    public void ticketChanged(UUID ticketId, UUID requesterId, String reference) {
        if (!enabled) {
            return;
        }
        Optional<AppUser> requester = users.findById(requesterId)
                .filter(user -> user.getEmail() != null && user.isEnabled() && !user.isErased());
        JavaMailSender sender = mailSender.getIfAvailable();
        if (requester.isEmpty() || sender == null) {
            return;
        }
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(requester.get().getEmail());
        message.setSubject("[SecureDesk] Ticket " + reference + " was updated");
        message.setText("Your ticket " + reference + " was updated.\n\n"
                + "Sign in to see what changed:\n" + baseUrl + "/tickets/" + ticketId + "\n\n"
                + "This message contains no ticket content on purpose.\n");
        try {
            sender.send(message);
            audit.event(AuditType.NOTIFICATION_SENT).system().target("ticket", ticketId).write();
        } catch (MailException e) {
            LOG.warn("notification for ticket {} could not be sent: {}", reference, e.getClass().getSimpleName());
            audit.event(AuditType.NOTIFICATION_FAILED).system().outcome(Outcome.FAILURE)
                    .target("ticket", ticketId).write();
        }
    }
}
