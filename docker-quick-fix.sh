#!/bin/bash

echo "🚀 SPAWN Docker Quick Fix Script"
echo "================================"
echo ""

# Stop any running containers
echo "🛑 Stopping existing containers..."
docker compose down --remove-orphans

# Clean up Docker cache aggressively  
echo "🧹 Cleaning Docker cache..."
docker system prune -f
docker builder prune -f

# Remove existing images to force rebuild
echo "🗑️  Removing existing SPAWN images..."
docker image rm spawn-main-frontend 2>/dev/null || true
docker image rm spawn-main-backend 2>/dev/null || true

# Pull base images to avoid download time during build
echo "📦 Pre-pulling base images..."
docker pull node:20-alpine
docker pull python:3.11-slim  
docker pull mongo:7.0

echo ""
echo "⚡ Starting optimized build..."
echo "================================"

# Build with no cache and optimized settings
DOCKER_BUILDKIT=1 docker compose build --no-cache --parallel

echo ""
if [ $? -eq 0 ]; then
    echo "✅ Build successful! Starting services..."
    docker compose up -d
    
    echo ""
    echo "🎉 SPAWN is starting up!"
    echo "📱 Frontend: http://localhost:3000"
    echo "🔧 Backend: http://localhost:8001"
    echo ""
    echo "📊 Checking container status..."
    docker compose ps
    
    echo ""
    echo "📋 To view logs:"
    echo "   docker compose logs -f frontend"
    echo "   docker compose logs -f backend"
    
else
    echo "❌ Build failed. Check the output above for errors."
    echo ""
    echo "🔍 Common fixes:"
    echo "   1. Check internet connection"
    echo "   2. Ensure Docker has enough resources (4GB+ RAM)"
    echo "   3. Try running: docker system prune -a"
    echo "   4. Check available disk space"
fi