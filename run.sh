#!/usr/bin/env bash
# DNS Defender AI - Quick start script (no kitty windows)
# Starts all services and shows logs in one terminal.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if services are already running
if podman ps --filter "name=dns-defender-ai" | grep -q "Up"; then
    echo "⚠️  Some services are already running."
    echo ""
    echo "Running containers:"
    podman ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
    echo ""
    read -p "Would you like to restart them? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "🛑 Stopping existing containers..."
        podman-compose -f docker-compose.yml down
        sleep 2
    else
        echo "✅ Exiting (use 'podman-compose down' to stop manually)"
        exit 0
    fi
fi

# Build images if needed (optional - comment out if you want to skip build)
if ! podman images --format '{{.Repository}}:{{.Tag}}' | grep -q 'dns-defender-ai_backend'; then
    echo "⚠️  Images not found. Building..."
    echo "This may take several minutes..."
    podman-compose -f docker-compose.yml build
fi

# Start services in the correct order
echo "🚀 Starting DNS Defender AI..."

podman-compose -f docker-compose.yml up -d postgres || {
    echo "❌ Failed to start PostgreSQL"
    exit 1
}
echo "  ✓ PostgreSQL started"
sleep 5

podman-compose -f docker-compose.yml up -d dns-resolver || {
    echo "❌ Failed to start DNS Resolver"
    exit 1
}
echo "  ✓ DNS Resolver started"
sleep 3

podman-compose -f docker-compose.yml up -d backend || {
    echo "❌ Failed to start Backend"
    exit 1
}
echo "  ✓ Backend started"
sleep 3

podman-compose -f docker-compose.yml up -d frontend || {
    echo "❌ Failed to start Frontend"
    exit 1
}
echo "  ✓ Frontend started"

# Wait a bit for everything to be healthy
echo ""
echo "⏳ Waiting for services to be healthy..."
sleep 10

# Show status
echo ""
echo "✅ All services running!"
echo ""
echo "📊 Container Status:"
podman ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

echo ""
echo "🌐 Access:"
echo "  • Dashboard: http://localhost:3000"
echo "  • API Docs:  http://localhost:8000/docs"
echo "  • DNS Server: 127.0.0.1:5354 (or 0.0.0.0:5354)"
echo ""
echo "💡 View logs:"
echo "  • All:   podman-compose logs -f"
echo "  • Pg:    podman logs -f dns-defender-ai_postgres_1"
echo "  • Backend: podman logs -f dns-defender-ai_backend_1"
echo "  • Frontend: podman logs -f dns-defender-ai_frontend_1"
echo "  • DNS:   podman logs -f dns-defender-ai_dns-resolver_1"
echo ""
echo "🧪 Test:"
echo "  • ./scripts/simulate-traffic.sh 127.0.0.1 5354"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ''
echo "Press Ctrl+C to stop monitoring (containers will keep running)"
echo "To stop everything:  podman-compose down"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"