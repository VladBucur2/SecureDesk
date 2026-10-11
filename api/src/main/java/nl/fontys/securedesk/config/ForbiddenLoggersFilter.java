package nl.fontys.securedesk.config;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.turbo.TurboFilter;
import ch.qos.logback.core.spi.FilterReply;
import org.slf4j.Marker;

import java.util.List;

/**
 * The forbidden-field rule of SC-09 applied to every logger, not only the audit stream
 * (BoK 6.2.5). With two Hibernate loggers at TRACE the PoC wrote the administrator's password
 * hash and encrypted TOTP secret into the log. A level is a setting anyone can change with one
 * environment variable, so this filter refuses those loggers below the level where they are
 * safe, whatever the configuration says:
 *
 * <ul>
 *   <li>loggers that print bound SQL values: never;</li>
 *   <li>web, security and container loggers, which print request bodies, cookies and headers
 *       at DEBUG: nothing below INFO.</li>
 * </ul>
 */
public class ForbiddenLoggersFilter extends TurboFilter {

    private static final List<String> NEVER = List.of(
            "org.hibernate.orm.jdbc.bind",
            "org.hibernate.orm.jdbc.extract",
            "org.hibernate.type");

    private static final List<String> INFO_AND_ABOVE = List.of(
            "org.hibernate.SQL",
            "org.springframework.web",
            "org.springframework.security",
            "org.springframework.http",
            "org.apache.coyote",
            "org.apache.tomcat",
            "org.apache.catalina",
            "com.mysql",
            "org.eclipse.angus.mail",
            "jakarta.mail");

    @Override
    public FilterReply decide(Marker marker, Logger logger, Level level, String format, Object[] params, Throwable t) {
        if (logger == null || level == null) {
            return FilterReply.NEUTRAL;
        }
        String name = logger.getName();
        for (String prefix : NEVER) {
            if (name.startsWith(prefix)) {
                return FilterReply.DENY;
            }
        }
        if (!level.isGreaterOrEqual(Level.INFO)) {
            for (String prefix : INFO_AND_ABOVE) {
                if (name.startsWith(prefix)) {
                    return FilterReply.DENY;
                }
            }
        }
        return FilterReply.NEUTRAL;
    }
}
