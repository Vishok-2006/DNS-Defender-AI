#!/usr/bin/env bash
# Send real DNS queries through the resolver so the full pipeline (resolver log ->
# monitor -> ML -> dashboard) can be demonstrated.
#   ./scripts/simulate-traffic.sh [resolver-ip] [port]
# For clients on the same machine as the resolver, queries show up as 127.0.0.1 / the docker gateway.
set -u
DNS_SERVER="${1:-127.0.0.1}"
DNS_PORT="${2:-53}"
command -v dig >/dev/null || { echo "dig not found (apt install dnsutils)"; exit 1; }
q() { dig @"$DNS_SERVER" -p "$DNS_PORT" "$@" +short +time=2 +tries=1 >/dev/null 2>&1 || true; }
rand() { LC_ALL=C tr -dc "$1" </dev/urandom | head -c "$2"; }

echo "[*] Benign traffic -> $DNS_SERVER:$DNS_PORT"
for d in github.com wikipedia.org docs.python.org stackoverflow.com raspberrypi.com; do q "$d"; sleep 0.3; done

echo "[*] DGA-style burst: 14 random names (these will not exist -> NXDOMAIN)"
tlds=(biz info top cc su xyz)
for i in $(seq 1 14); do
  q "$(rand 'a-z0-9' $((11 + RANDOM % 6)))"."${tlds[$((i % ${#tlds[@]}))]}"; sleep 0.2
done

echo "[*] DNS tunnelling-style TXT lookups with encoded labels"
for i in 1 2 3 4; do q "$(rand 'a-f0-9' 44).s$i.exfil-tunnel.example" TXT; sleep 0.3; done

echo "[*] Phishing-style names"
for d in login-verify-secure-account-update.xyz paypal-account-suspend-confirm-login.top; do q "$d"; done

echo "[+] Done. Open the dashboard (default http://<host>:3000) to see the alerts."
