# SPAWN Docker Setup Guide

## Quick Start

1. **Clone and Navigate to the Project**
```bash
git clone <repository-url>
cd SPAWN
```

2. **Build and Run with Docker Compose**
```bash
docker compose up --build
```

3. **Access the Application**
- Frontend: http://localhost:3000
- Backend API: http://localhost:8001
- MongoDB: localhost:27017

## Troubleshooting

### If you get package installation errors:

The most common issue is with the `libgdk-pixbuf2.0-dev` package. This has been fixed in the updated Dockerfile.backend to use `libgdk-pixbuf-xlib-2.0-dev`.

### If containers fail to start:

1. **Check Docker and Docker Compose versions:**
```bash
docker --version
docker compose version
```

2. **Clean build (if you have old images):**
```bash
docker compose down
docker system prune -f
docker compose up --build
```

3. **View logs for debugging:**
```bash
# All services
docker compose logs

# Specific service
docker compose logs backend
docker compose logs frontend
docker compose logs mongodb
```

### Memory/Performance Issues:

If you're on a resource-constrained system:

```bash
# Reduce build parallelism
docker compose up --build --parallel 1
```

## Development Mode

For development with hot reload:

```bash
# Run with bind mounts (already configured in docker-compose.yml)
docker compose up
```

Changes to your code will be reflected automatically.

## Production Deployment

1. **Create production environment file:**
```bash
cp .env.example .env.production
# Edit .env.production with your production values
```

2. **Build for production:**
```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build
```

## Database Access

To access MongoDB directly:

```bash
# Connect to MongoDB container
docker exec -it spawn_mongodb mongosh

# Or using external client
mongosh "mongodb://admin:password123@localhost:27017/spawn_db?authSource=admin"
```

## Port Configuration

Default ports used:
- Frontend: 3000
- Backend: 8001  
- MongoDB: 27017

To change ports, modify the `docker-compose.yml` file.

## Security Notes

⚠️ **Important for Production:**

1. Change default MongoDB credentials in `docker-compose.yml`
2. Use proper environment variables
3. Configure proper CORS origins
4. Use HTTPS in production
5. Implement proper authentication

## Container Health Checks

All containers have health checks configured:

```bash
# Check container health
docker compose ps

# View health check logs
docker inspect spawn_backend | grep -A 10 Health
```

## Backup and Data Persistence

MongoDB data is persisted in Docker volume `mongodb_data`:

```bash
# Backup database
docker exec spawn_mongodb mongodump --out /backup --db spawn_db

# List volumes
docker volume ls

# Backup volume (while containers are stopped)
docker run --rm -v mongodb_data:/data -v $(pwd):/backup alpine tar czf /backup/mongodb_backup.tar.gz -C /data .
```

## Common Issues and Solutions

### 1. Port Already in Use
```bash
# Check what's using the port
lsof -i :3000
lsof -i :8001

# Kill processes or change ports in docker-compose.yml
```

### 2. Permission Issues (Linux/macOS)
```bash
# Fix Docker permissions
sudo usermod -aG docker $USER
# Logout and login again
```

### 3. Build Cache Issues
```bash
# Clear build cache
docker builder prune
docker compose build --no-cache
```

### 4. Network Issues
```bash
# Reset Docker networks
docker network prune
```

## Monitoring

View real-time logs:

```bash
# Follow all logs
docker compose logs -f

# Follow specific service
docker compose logs -f backend
```

Monitor resource usage:

```bash
# Container stats
docker stats

# Specific container
docker stats spawn_backend
```