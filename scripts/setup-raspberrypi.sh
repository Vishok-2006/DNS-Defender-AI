#!/usr/bin/env bash
# DNS Defender AI - Raspberry Pi / Debian setup.
# Run from the repository root as a normal user with sudo rights:  ./scripts/setup-raspberrypi.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== DNS Defender AI setup =="
arch=$(uname -m)
case "$arch" in aarch64|x86_64) ;; *) echo "Unsupported architecture '$arch' (need 64-bit OS: aarch64 or x86_64)"; exit 1;; esac

# 1. Docker
if ! command -v docker >/dev/null; then
  echo "[1/5] Installing Docker..."
  curl -fsSL https://get.docker.com | sudo sh
else
  echo "[1/5] Docker already installed"
fi
DOCKER="docker"
docker info >/dev/null 2>&1 || DOCKER="sudo docker"   # group membership only applies after re-login

# 2. Free port 53 (systemd-resolved's stub listener conflicts with the resolver container)
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  echo "[2/5] Disabling the systemd-resolved stub listener on port 53..."
  sudo mkdir -p /etc/systemd/resolved.conf.d
  printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/dnsdefender.conf >/dev/null
  sudo systemctl restart systemd-resolved
else
  echo "[2/5] systemd-resolved not active - nothing to do"
fi

# 3. Configuration (.env) with generated secrets
if [ ! -f .env ]; then
  echo "[3/5] Creating .env with generated secrets..."
  cp .env.example .env
  sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(openssl rand -hex 24)|" .env
  sed -i "s|^API_KEY=.*|API_KEY=$(openssl rand -hex 16)|" .env
  chmod 600 .env
  echo "      API key for the dashboard: $(grep '^API_KEY=' .env | cut -d= -f2)"
else
  echo "[3/5] .env exists - keeping it"
fi

# 4. Firewall: the resolver must never be an open resolver on the internet
if command -v ufw >/dev/null && sudo ufw status | grep -q "Status: active"; then
  echo "[4/5] Allowing DNS and the dashboard from private LAN ranges only..."
  for net in 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12; do
    sudo ufw allow from "$net" to any port 53 proto udp >/dev/null
    sudo ufw allow from "$net" to any port 53 proto tcp >/dev/null
    sudo ufw allow from "$net" to any port "$(grep -E '^UI_PORT=' .env | cut -d= -f2 | cut -d' ' -f1)" proto tcp >/dev/null
  done
else
  echo "[4/5] ufw not active - make sure port 53 is NOT reachable from the internet"
fi

# 5. Build and start
echo "[5/5] Building and starting the stack (first build on a Pi takes a few minutes)..."
$DOCKER compose up -d --build

ip=$(hostname -I | awk '{print $1}')
echo "---------------------------------------------------------------"
echo "Dashboard : http://$ip:$(grep -E '^UI_PORT=' .env | cut -d= -f2 | cut -d' ' -f1)"
echo "DNS server: $ip:53   (point your router's DHCP DNS at this address)"
echo "Test      : ./scripts/simulate-traffic.sh $ip"
