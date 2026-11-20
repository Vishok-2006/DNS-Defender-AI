FROM docker.io/library/alpine:3.20
RUN apk add --no-cache dnsmasq bind-tools tini
COPY dnsmasq.conf /etc/dnsmasq.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
EXPOSE 53/udp 53/tcp
HEALTHCHECK --interval=15s --timeout=4s --start-period=5s --retries=3 \
  CMD dig +time=2 +tries=1 +short @127.0.0.1 health.check.local | grep -q '^127.0.0.1$' || exit 1
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
