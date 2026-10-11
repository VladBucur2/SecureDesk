package nl.fontys.securedesk.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.format.DateTimeFormatter;
import java.time.ZoneOffset;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Sends every audit event to the log collector within seconds, over syslog with TLS: RFC 5424
 * messages with octet-counting framing (RFC 5425), TLS 1.3 only, the collector's certificate
 * checked against the internal CA and its name, and this API's own client certificate, so the
 * collector accepts only known senders (BoK 6.2.4). This is what defeats branch 2 of the G4
 * attack tree: a record that has left the host can no longer be erased on it.
 *
 * <p>Events wait in a bounded queue, so a collector outage never slows a request. When the
 * queue is full the oldest event is dropped from the queue (it is still in the database) and
 * the drop is counted and logged.
 */
@Component
public class AuditForwarder implements SmartLifecycle {

    private static final Logger LOG = LoggerFactory.getLogger(AuditForwarder.class);

    /** local4: the facility BoK 6.2.4 gave the SecureDesk application. */
    private static final int FACILITY_LOCAL4 = 20;
    private static final int SEVERITY_WARNING = 4;
    private static final int SEVERITY_INFO = 6;
    /** 32473 is the private enterprise number reserved for documentation (RFC 5612). */
    private static final String SD_ID = "securedesk@32473";
    private static final DateTimeFormatter TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'").withZone(ZoneOffset.UTC);

    private final AuditProperties.Forward config;
    private final SslBundles sslBundles;
    private final BlockingQueue<byte[]> queue;
    private final AtomicLong dropped = new AtomicLong();
    private final String procId = String.valueOf(ProcessHandle.current().pid());

    private volatile boolean running;
    private Thread sender;
    private SSLSocket socket;

    public AuditForwarder(AuditProperties properties, SslBundles sslBundles) {
        this.config = properties.forward();
        this.sslBundles = sslBundles;
        this.queue = new ArrayBlockingQueue<>(Math.max(1, config.queueCapacity()));
    }

    void forward(AuditEvent event) {
        if (!config.enabled()) {
            return;
        }
        byte[] frame = frame(event);
        while (!queue.offer(frame)) {
            queue.poll();
            long total = dropped.incrementAndGet();
            if (total == 1 || total % 1000 == 0) {
                LOG.warn("audit forwarding queue full: {} events dropped from the queue so far", total);
            }
        }
    }

    /** One RFC 5424 message, framed as "LENGTH SP MESSAGE" (RFC 5425 section 4.3). */
    byte[] frame(AuditEvent event) {
        int severity = "SUCCESS".equals(event.getOutcome()) && !event.isAlert() ? SEVERITY_INFO : SEVERITY_WARNING;
        String structuredData = "[" + SD_ID
                + " seq=\"" + event.getSeq() + "\""
                + " category=\"" + sdEscape(event.getCategory()) + "\""
                + " outcome=\"" + sdEscape(event.getOutcome()) + "\""
                + " alert=\"" + event.isAlert() + "\"]";
        String message = "<" + (FACILITY_LOCAL4 * 8 + severity) + ">1 "
                + TIMESTAMP.format(event.getTs()) + " "
                + config.hostname() + " securedesk " + procId + " "
                + msgId(event.getEventType()) + " "
                + structuredData + " "
                + event.toJsonLine();
        byte[] body = message.getBytes(StandardCharsets.UTF_8);
        byte[] prefix = (body.length + " ").getBytes(StandardCharsets.US_ASCII);
        byte[] frame = new byte[prefix.length + body.length];
        System.arraycopy(prefix, 0, frame, 0, prefix.length);
        System.arraycopy(body, 0, frame, prefix.length, body.length);
        return frame;
    }

    private static String msgId(String eventType) {
        return eventType.length() <= 32 ? eventType : eventType.substring(0, 32);
    }

    /** RFC 5424 section 6.3.3: '"', '\' and ']' are escaped inside PARAM-VALUE. */
    private static String sdEscape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("]", "\\]");
    }

    // ---- the sender ----------------------------------------------------------------------------

    @Override
    public void start() {
        if (!config.enabled()) {
            return;
        }
        running = true;
        sender = Thread.ofVirtual().name("audit-forwarder").start(this::sendLoop);
    }

    @Override
    public void stop() {
        running = false;
        if (sender != null) {
            sender.interrupt();
        }
        closeSocket();
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    private void sendLoop() {
        long backoffMillis = 1_000;
        byte[] pending = null;
        while (running) {
            try {
                if (pending == null) {
                    pending = queue.poll(1, TimeUnit.SECONDS);
                    if (pending == null) {
                        continue;
                    }
                }
                OutputStream out = connection().getOutputStream();
                out.write(pending);
                out.flush();
                pending = null;
                backoffMillis = 1_000;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (IOException | RuntimeException e) {
                closeSocket();
                LOG.warn("audit forwarding to {}:{} failed ({}); retrying in {} ms",
                        config.host(), config.port(), e.getClass().getSimpleName(), backoffMillis);
                try {
                    Thread.sleep(backoffMillis);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return;
                }
                backoffMillis = Math.min(backoffMillis * 2, 30_000);
            }
        }
    }

    private SSLSocket connection() throws IOException {
        if (socket != null && !socket.isClosed()) {
            return socket;
        }
        SSLSocket created = (SSLSocket) sslBundles.getBundle(config.sslBundle())
                .createSslContext().getSocketFactory().createSocket();
        SSLParameters parameters = created.getSSLParameters();
        parameters.setProtocols(new String[] {"TLSv1.3"});
        // An SSLSocket does not check the server's name unless told to.
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        created.setSSLParameters(parameters);
        created.connect(new InetSocketAddress(config.host(), config.port()), 5_000);
        created.startHandshake();
        socket = created;
        LOG.info("audit forwarding connected to {}:{} ({})", config.host(), config.port(),
                created.getSession().getProtocol());
        return created;
    }

    private void closeSocket() {
        SSLSocket current = socket;
        socket = null;
        if (current != null) {
            try {
                current.close();
            } catch (IOException ignored) {
                // closing a broken connection
            }
        }
    }
}
