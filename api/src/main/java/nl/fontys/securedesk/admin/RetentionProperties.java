package nl.fontys.securedesk.admin;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * SR-10 and SC-11: closed tickets are deleted after a configurable period, 24 months by default.
 * The hard maximum is deployment configuration, out of an administrator's reach, so the period
 * cannot be set beyond what the operator has agreed to.
 */
@ConfigurationProperties("securedesk.retention")
public record RetentionProperties(
        @DefaultValue("24") int defaultMonths,
        @DefaultValue("60") int maxMonths,
        @DefaultValue("0 15 3 * * *") String cron) {
}
