#!/bin/sh
# DNS Defender AI - resolver entrypoint.
#  * builds the upstream list from DNS_UPSTREAM_SERVERS
#  * keeps the blocklist (a dnsmasq servers-file) in sync: dnsmasq re-reads it on SIGHUP
#  * keeps the query log from growing without bound
set -eu

RULES_FILE="${RULES_FILE:-/rules/blocked.conf}"
LOG_FILE="${LOG_FILE:-/var/log/dnsmasq/queries.log}"
CONF="${DNSMASQ_CONF:-/etc/dnsmasq.conf}"
UPSTREAMS="${DNS_UPSTREAM_SERVERS:-1.1.1.1,8.8.8.8}"
PORT="${DNS_LISTEN_PORT:-53}"
LOG_MAX_BYTES="${LOG_MAX_BYTES:-52428800}"
RULES_OWNER_UID="${RULES_OWNER_UID:-10001}"   # uid of the backend container user

RULES_DIR=$(dirname "$RULES_FILE")
mkdir -p "$RULES_DIR" "$(dirname "$LOG_FILE")"
[ -f "$RULES_FILE" ] || echo "# Managed by DNS Defender AI" > "$RULES_FILE"
chmod 644 "$RULES_FILE"
# let the (non-root) backend replace the rules file atomically
chown "$RULES_OWNER_UID" "$RULES_DIR" 2>/dev/null || chmod 777 "$RULES_DIR" || true
: >> "$LOG_FILE"
chmod 644 "$LOG_FILE"

set --
OLDIFS=$IFS; IFS=','
for s in $UPSTREAMS; do
    case "$s" in
        ""|*[!0-9a-fA-F.:]*) echo "[resolver] invalid upstream '$s'" >&2; exit 1 ;;
    esac
    set -- "$@" "--server=$s"
done
IFS=$OLDIFS

dnsmasq -k -C "$CONF" --port="$PORT" --log-facility="$LOG_FILE" --servers-file="$RULES_FILE" "$@" &
DNS_PID=$!
trap 'kill -TERM "$DNS_PID" 2>/dev/null; wait "$DNS_PID" 2>/dev/null; exit 0' TERM INT

echo "[resolver] dnsmasq started (pid $DNS_PID), upstreams: $UPSTREAMS, port $PORT"
last=$(cksum < "$RULES_FILE")
while kill -0 "$DNS_PID" 2>/dev/null; do
    sleep 1
    now=$(cksum < "$RULES_FILE" 2>/dev/null || echo missing)
    if [ "$now" != "$last" ]; then
        kill -HUP "$DNS_PID" && echo "[resolver] blocklist changed - dnsmasq reloaded"
        last=$now
    fi
    # dnsmasq re-creates its log as 0660 owned by its own user; the backend runs as a
    # different uid and only needs read access, so restore world-readable.
    chmod 644 "$LOG_FILE" 2>/dev/null || true
    size=$(wc -c < "$LOG_FILE" 2>/dev/null || echo 0)
    if [ "$size" -gt "$LOG_MAX_BYTES" ]; then
        : > "$LOG_FILE"   # dnsmasq appends (O_APPEND), the backend tailer detects the truncation
        echo "[resolver] query log truncated (> $LOG_MAX_BYTES bytes)"
    fi
done
wait "$DNS_PID"
