# The log collector of the monitoring zone (BoK 2.3, 5.3.1): rsyslog receiving RFC 5424 over
# TLS (RFC 5425) from known senders only, writing to a volume no other container mounts.
FROM ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends rsyslog rsyslog-gnutls \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10002 collector \
 && useradd --system --uid 10002 --gid collector --no-create-home --shell /usr/sbin/nologin collector \
 && mkdir -p /var/log/securedesk /var/spool/rsyslog \
 && chown collector:collector /var/log/securedesk /var/spool/rsyslog
COPY rsyslog.conf /etc/rsyslog.conf
USER 10002
EXPOSE 6514
ENTRYPOINT ["rsyslogd", "-n", "-f", "/etc/rsyslog.conf", "-i", "/tmp/rsyslogd.pid"]
