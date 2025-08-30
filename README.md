# SPAWN - Web Application Vulnerability Scanner

<div align="center">

![SPAWN Logo](https://img.shields.io/badge/SPAWN-Vulnerability%20Scanner-red?style=for-the-badge&logo=security&logoColor=white)

[![Docker](https://img.shields.io/badge/Docker-Ready-blue?style=flat&logo=docker)](https://www.docker.com/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Backend-green?style=flat&logo=fastapi)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-Frontend-blue?style=flat&logo=react)](https://reactjs.org/)
[![MongoDB](https://img.shields.io/badge/MongoDB-Database-green?style=flat&logo=mongodb)](https://mongodb.com/)

**Professional vulnerability scanning powered by Wapiti with modern web interface**

</div>

## 🚀 Features

- **🔍 Comprehensive Scanning**: 33+ vulnerability detection modules
- **📊 Real-time Dashboard**: Live scan progress and results
- **📈 Advanced Analytics**: Vulnerability trends and statistics  
- **📄 Multiple Export Formats**: PDF, CSV, HTML, JSON reports
- **🔄 WebSocket Updates**: Real-time scan status notifications
- **⚙️ Flexible Configuration**: Custom scan parameters and modules
- **🛡️ Security Focus**: Built for cybersecurity professionals

## 🏃‍♂️ Quick Start (Docker)

### Prerequisites
- Docker Desktop or Docker Engine
- Docker Compose v2
- 2GB+ available disk space
- Ports 3000, 8001, 27017 available

### 1. Clone Repository
```bash
git clone <repository-url>
cd SPAWN
```

### 2. Start Application
```bash
docker compose up --build
```

### 3. Access Application
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8001/api
- **API Docs**: http://localhost:8001/docs

## 🐛 Troubleshooting Docker Issues

If you encounter the `libgdk-pixbuf2.0-dev` error mentioned in your issue, this has been **FIXED** in the updated Dockerfile.

### Automated Fix
```bash
./docker-troubleshoot.sh
```

### Manual Troubleshooting

**1. Package Installation Error**
```bash
# Clean build cache and rebuild
docker system prune -f
docker compose down
docker compose up --build
```

**2. Port Conflicts**
```bash
# Check what's using ports
lsof -i :3000
lsof -i :8001
lsof -i :27017

# Kill conflicting processes or modify ports in docker-compose.yml
```

**3. Permission Issues (Linux/macOS)**
```bash
sudo usermod -aG docker $USER
# Logout and login again
```

**4. View Detailed Logs**
```bash
# All services
docker compose logs

# Specific service
docker compose logs backend
docker compose logs frontend
docker compose logs mongodb
```

## 📁 Project Structure

```
SPAWN/
├── 🖥️  frontend/           # React application
│   ├── src/
│   │   ├── App.js          # Main application component
│   │   └── components/     # UI components
│   ├── package.json
│   └── Dockerfile.frontend
├── ⚙️  backend/            # FastAPI server  
│   ├── server.py           # Main application
│   ├── requirements.txt
│   └── .env
├── 🗄️  mongo-init/        # Database initialization
├── 🐳 docker-compose.yml   # Docker services configuration
├── 📚 DOCKER_SETUP.md     # Detailed Docker guide
└── 🔧 docker-troubleshoot.sh # Automated troubleshooting
```

## 🔧 Development

### Backend Development
```bash
cd backend
pip install -r requirements.txt
uvicorn server:app --reload --host 0.0.0.0 --port 8001
```

### Frontend Development  
```bash
cd frontend
yarn install
yarn start
```

### Database Access
```bash
# Connect to MongoDB
mongosh "mongodb://admin:password123@localhost:27017/spawn_db?authSource=admin"

# Or via Docker
docker exec -it spawn_mongodb mongosh
```

## 🛡️ Vulnerability Modules

SPAWN integrates with Wapiti and supports 33+ security modules:

| Module | Description |
|--------|-------------|
| `exec` | Command execution vulnerabilities |
| `file` | File inclusion vulnerabilities |
| `sql` | SQL injection detection |
| `xss` | Cross-site scripting |
| `csrf` | Cross-site request forgery |
| `ssrf` | Server-side request forgery |
| `backup` | Backup file detection |
| `cms` | CMS-specific vulnerabilities |
| And 25+ more... | |

## 📊 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/` | GET | Service status |
| `/api/modules` | GET | Available scan modules |
| `/api/scans` | GET/POST | Scan configurations |
| `/api/scans/{id}/start` | POST | Start vulnerability scan |
| `/api/scans/{id}/stop` | POST | Stop running scan |
| `/api/results` | GET | All scan results |
| `/api/results/{id}` | GET | Specific scan result |
| `/api/results/{id}/export/{format}` | GET | Export results |
| `/ws` | WebSocket | Real-time updates |

## ⚙️ Configuration

### Environment Variables

**Backend (.env)**
```bash
MONGO_URL=mongodb://localhost:27017
DB_NAME=spawn_db  
CORS_ORIGINS=*
```

**Frontend (.env)**
```bash
REACT_APP_BACKEND_URL=http://localhost:8001
```

### Docker Compose Ports
- Frontend: `3000:3000`
- Backend: `8001:8001`
- MongoDB: `27017:27017`

## 🔐 Security Notes

**⚠️ Important for Production:**

1. **Change default MongoDB credentials**
2. **Configure proper CORS origins**  
3. **Use HTTPS in production**
4. **Implement authentication**
5. **Restrict database access**

## 📚 Documentation

- [Docker Setup Guide](DOCKER_SETUP.md) - Detailed Docker configuration
- [API Documentation](http://localhost:8001/docs) - Interactive API docs
- [Wapiti Documentation](https://wapiti-scanner.github.io/) - Scanner details

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/awesome-feature`)
3. Commit changes (`git commit -am 'Add awesome feature'`)
4. Push to branch (`git push origin feature/awesome-feature`)
5. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

Having issues? Check our troubleshooting resources:

1. **Run the troubleshoot script**: `./docker-troubleshoot.sh`
2. **Check Docker logs**: `docker compose logs`
3. **Review the setup guide**: [DOCKER_SETUP.md](DOCKER_SETUP.md)
4. **Open an issue** with detailed error messages

---

<div align="center">

**Built with ❤️ for cybersecurity professionals**

[🐳 Docker Hub](https://hub.docker.com/) • [📚 Documentation](DOCKER_SETUP.md) • [🐛 Issues](../../issues) • [💡 Discussions](../../discussions)

</div>
