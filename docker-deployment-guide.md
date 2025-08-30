# SPAWN Docker Deployment Guide

## Overview
SPAWN is a comprehensive web-based vulnerability scanner that provides a modern GUI for the Wapiti security testing tool. This guide covers Docker deployment using docker-compose.

## Prerequisites
- Docker Engine 20.10+
- Docker Compose 2.0+
- At least 2GB RAM available
- 10GB free disk space

## Quick Start

### 1. Clone and Build
```bash
# Navigate to the SPAWN directory
cd /path/to/spawn

# Build and start all services
docker-compose up --build -d
```

### 2. Verify Services
```bash
# Check service status
docker-compose ps

# View logs
docker-compose logs -f backend
docker-compose logs -f frontend
```

### 3. Access SPAWN
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8001/api
- **MongoDB**: localhost:27017

## Configuration

### Environment Variables

#### Backend (.env or docker-compose.yml)
```bash
MONGO_URL=mongodb://admin:password123@mongodb:27017/spawn_db?authSource=admin
DB_NAME=spawn_db
CORS_ORIGINS=*
```

#### Frontend (.env or docker-compose.yml)
```bash
REACT_APP_BACKEND_URL=http://localhost:8001
WDS_SOCKET_PORT=443
```

### MongoDB Configuration
Default credentials (change in production):
- Username: `admin`
- Password: `password123`
- Database: `spawn_db`

## Production Deployment

### 1. Security Hardening
```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  mongodb:
    environment:
      MONGO_INITDB_ROOT_USERNAME: ${MONGO_USER}
      MONGO_INITDB_ROOT_PASSWORD: ${MONGO_PASSWORD}
    volumes:
      - mongodb_data:/data/db
    networks:
      - internal
    # Remove port exposure for security

  backend:
    environment:
      MONGO_URL: "mongodb://${MONGO_USER}:${MONGO_PASSWORD}@mongodb:27017/${MONGO_DB}?authSource=admin"
      CORS_ORIGINS: "https://yourdomain.com"
    networks:
      - internal

  frontend:
    environment:
      REACT_APP_BACKEND_URL: "https://api.yourdomain.com"
    networks:
      - internal

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - frontend
      - backend
    networks:
      - internal

networks:
  internal:
    driver: bridge
    internal: true
```

### 2. Environment File (.env)
```bash
MONGO_USER=secure_admin
MONGO_PASSWORD=very_secure_password_123!
MONGO_DB=spawn_production
DOMAIN=yourdomain.com
```

## Service Management

### Starting Services
```bash
# Start all services
docker-compose up -d

# Start specific service
docker-compose up -d backend

# Rebuild and start
docker-compose up --build -d
```

### Stopping Services
```bash
# Stop all services
docker-compose down

# Stop and remove volumes (WARNING: deletes data)
docker-compose down -v
```

### Scaling
```bash
# Scale backend for load balancing
docker-compose up -d --scale backend=3
```

## Monitoring and Maintenance

### Health Checks
```bash
# Check container health
docker-compose ps

# Check specific service logs
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f mongodb
```

### Database Backup
```bash
# Backup MongoDB
docker exec spawn_mongodb mongodump --authenticationDatabase admin -u admin -p password123 --out /backup

# Copy backup from container
docker cp spawn_mongodb:/backup ./mongodb_backup_$(date +%Y%m%d)
```

### Updates
```bash
# Pull latest images and rebuild
docker-compose pull
docker-compose up --build -d

# Remove old images
docker image prune -f
```

## Troubleshooting

### Common Issues

#### 1. Wapiti Not Found
If you see "wapiti: command not found" errors:
```bash
# Check if Wapiti is installed in backend container
docker exec -it spawn_backend which wapiti
docker exec -it spawn_backend wapiti --version
```

#### 2. MongoDB Connection Issues
```bash
# Check MongoDB logs
docker-compose logs mongodb

# Test MongoDB connection
docker exec -it spawn_mongodb mongo -u admin -p password123
```

#### 3. Frontend Can't Connect to Backend
```bash
# Check backend health
curl http://localhost:8001/api/

# Check backend logs for CORS issues
docker-compose logs backend
```

#### 4. Permission Issues
```bash
# Fix file permissions
sudo chown -R $USER:$USER ./
docker-compose down
docker-compose up --build -d
```

### Resource Requirements
- **Minimum**: 2 CPU cores, 4GB RAM, 10GB disk
- **Recommended**: 4 CPU cores, 8GB RAM, 50GB disk
- **Network**: All containers communicate via internal Docker network

### Data Persistence
- MongoDB data: Stored in `mongodb_data` Docker volume
- Scan reports: Temporarily stored in backend container `/tmp`
- Logs: Available via `docker-compose logs`

### Security Considerations
1. Change default MongoDB passwords
2. Use HTTPS in production
3. Implement proper firewall rules
4. Regular security updates
5. Monitor resource usage
6. Backup data regularly

## Support
For issues with Docker deployment:
1. Check service logs: `docker-compose logs <service>`
2. Verify network connectivity between services
3. Ensure all required ports are available
4. Check Docker and docker-compose versions