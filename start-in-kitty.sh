#!/usr/bin/env bash
# DNS Defender AI - Launch stack and open logs in separate Kitty windows / tabs
# Works with Podman and Podman-Compose.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🛡️  ================================================================"
echo "    DNS Defender AI - Podman Launcher"
echo "================================================================"

# Check requirements
if ! command -v podman &> /dev/null; then
    echo "❌ podman is not installed."
    exit 1
fi

if ! command -v podman-compose &> /dev/null && ! podman compose version &> /dev/null; then
    echo "❌ podman-compose is not installed."
    exit 1
fi

COMPOSE_CMD="podman-compose"
if ! command -v podman-compose &> /dev/null; then
    COMPOSE_CMD="podman compose"
fi

# Ensure .env exists
if [ ! -f .env ]; then
    echo "⚙️  Creating .env from .env.example..."
    cp .env.example .env
    sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(openssl rand -hex 16)|" .env
    sed -i "s|^DNS_PORT=.*|DNS_PORT=5354|" .env
fi

# Build containers if needed
echo "🔨 Building OCI images with Podman..."
$COMPOSE_CMD -f docker-compose.yml build

# Start services
echo "🚀 Starting containers..."
$COMPOSE_CMD -f docker-compose.yml up -d

echo ""
echo "⏳ Waiting for containers to become ready..."
sleep 5

# Verify container status
echo ""
echo "📊 Running Services:"
podman ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo ""
echo "🌐 Endpoints:"
echo "  • Dashboard UI:  http://localhost:3000"
echo "  • Backend API:   http://localhost:8000/docs"
echo "  • DNS Resolver:  127.0.0.1:5354 (UDP/TCP)"

# Helper function to open log window in Kitty
launch_kitty_window() {
    local title="$1"
    local container="$2"

    # Try kitty @ launch if remote control socket is available, otherwise spawn detached kitty window
    if [ -n "${KITTY_LISTEN_ON:-}" ] || kitty @ ls &>/dev/null; then
        kitty @ launch --type=tab --title="$title" --cwd="$SCRIPT_DIR" \
            bash -c "echo '=== Logs for $container ==='; podman logs -f $container; read" &
    else
        kitty --detach --title="$title" --directory="$SCRIPT_DIR" \
            bash -c "echo '=== Logs for $container ==='; podman logs -f $container; read" &
    fi
}

if command -v kitty &> /dev/null; then
    echo ""
    echo "🖥️  Opening logs in Kitty terminals..."
    launch_kitty_window "PostgreSQL Logs" "dns-defender-ai_postgres_1"
    launch_kitty_window "DNS Resolver Logs" "dns-defender-ai_dns-resolver_1"
    launch_kitty_window "Backend API Logs" "dns-defender-ai_backend_1"
    launch_kitty_window "Frontend UI Logs" "dns-defender-ai_frontend_1"
    echo "✅ Kitty windows launched!"
else
    echo "⚠️  kitty terminal not found; skipping log window creation."
fi

echo ""
echo "🧪 Run simulation traffic to test detection:"
echo "  ./scripts/simulate-traffic.sh 127.0.0.1 5354"
echo ""
echo "🛑 To stop all containers:"
echo "  podman-compose down"
echo "================================================================"
