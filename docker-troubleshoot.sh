#!/bin/bash

echo "🐳 SPAWN Docker Troubleshoot Script"
echo "=================================="

# Check Docker installation
echo "📋 Checking Docker installation..."
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker compose &> /dev/null; then
    echo "❌ Docker Compose is not installed or not using v2. Please update Docker."
    exit 1
fi

echo "✅ Docker $(docker --version)"
echo "✅ $(docker compose version)"

# Check if Docker daemon is running
echo ""
echo "🔍 Checking Docker daemon..."
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker daemon is not running. Please start Docker."
    exit 1
fi
echo "✅ Docker daemon is running"

# Check available ports
echo ""
echo "🔌 Checking port availability..."

check_port() {
    local port=$1
    local service=$2
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo "⚠️  Port $port is already in use (needed for $service)"
        echo "   Process: $(lsof -Pi :$port -sTCP:LISTEN | tail -1)"
        return 1
    else
        echo "✅ Port $port is available ($service)"
        return 0
    fi
}

PORTS_AVAILABLE=true
check_port 3000 "Frontend" || PORTS_AVAILABLE=false
check_port 8001 "Backend" || PORTS_AVAILABLE=false
check_port 27017 "MongoDB" || PORTS_AVAILABLE=false

if [ "$PORTS_AVAILABLE" = false ]; then
    echo ""
    echo "💡 To fix port conflicts:"
    echo "   1. Stop conflicting services"
    echo "   2. Or modify ports in docker-compose.yml"
fi

# Check disk space
echo ""
echo "💾 Checking disk space..."
AVAILABLE_SPACE=$(df . | tail -1 | awk '{print $4}')
REQUIRED_SPACE=2097152  # 2GB in KB

if [ "$AVAILABLE_SPACE" -lt "$REQUIRED_SPACE" ]; then
    echo "⚠️  Low disk space: $(($AVAILABLE_SPACE / 1024))MB available, 2GB recommended"
    echo "   Consider cleaning up: docker system prune -f"
else
    echo "✅ Sufficient disk space: $(($AVAILABLE_SPACE / 1024))MB available"
fi

# Check Docker resources
echo ""
echo "🖥️  Checking Docker resources..."
echo "Memory: $(docker system df | grep 'Total' | awk '{print $4}')"

# Provide troubleshooting steps
echo ""
echo "🔧 Quick Fix Commands:"
echo "=================================="
echo "Clean Docker cache:"
echo "  docker system prune -f"
echo ""
echo "Rebuild from scratch:"
echo "  docker compose down"
echo "  docker compose up --build"
echo ""
echo "View logs:"
echo "  docker compose logs backend"
echo "  docker compose logs frontend"
echo ""
echo "Fix permissions (Linux/macOS):"
echo "  sudo usermod -aG docker \$USER"
echo "  # Then logout and login again"

echo ""
echo "🏁 Troubleshoot complete!"

# Ask if user wants to attempt automatic fixes
echo ""
read -p "Would you like to clean Docker cache and rebuild? (y/N): " response
if [[ "$response" =~ ^[Yy]$ ]]; then
    echo "🧹 Cleaning Docker cache..."
    docker system prune -f
    
    echo "🔨 Rebuilding containers..."
    docker compose down
    docker compose up --build -d
    
    echo "✅ Rebuild complete! Check http://localhost:3000"
fi