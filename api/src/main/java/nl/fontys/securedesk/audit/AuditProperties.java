package nl.fontys.securedesk.audit;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * @param forward where audit events go off-host
 */
@ConfigurationProperties("securedesk.audit")
public record AuditProperties(@DefaultValue Forward forward) {

    /**
     * @param enabled       off in tests and in a bare local run
     * @param host          the log collector in the monitoring zone
     * @param port          6514, syslog over TLS (RFC 5425)
     * @param sslBundle     the Spring SSL bundle with this API's client certificate and the CA
     * @param hostname      the HOSTNAME field of every RFC 5424 message
     * @param queueCapacity events held while the collector is unreachable; the oldest go first
     */
    public record Forward(
            @DefaultValue("false") boolean enabled,
            @DefaultValue("collector") String host,
            @DefaultValue("6514") int port,
            @DefaultValue("syslog") String sslBundle,
            @DefaultValue("securedesk-api") String hostname,
            @DefaultValue("10000") int queueCapacity) {
    }
}
