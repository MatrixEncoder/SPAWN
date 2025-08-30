# SPAWN Docker Troubleshooting Script for Windows PowerShell
Write-Host "SPAWN Docker Troubleshooting Script" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan

# Check Docker status
Write-Host "`n1. Checking Docker status..." -ForegroundColor Yellow
try {
    docker --version
    docker-compose --version
    Write-Host "✓ Docker is installed and running" -ForegroundColor Green
} catch {
    Write-Host "✗ Docker is not running or not installed" -ForegroundColor Red
    Write-Host "Please start Docker Desktop and try again." -ForegroundColor Yellow
    exit 1
}

# Check if services are running
Write-Host "`n2. Checking SPAWN services..." -ForegroundColor Yellow
$services = docker-compose ps --services
if ($services) {
    Write-Host "✓ Docker Compose file found" -ForegroundColor Green
    docker-compose ps
} else {
    Write-Host "✗ No docker-compose.yml found or no services running" -ForegroundColor Red
}

# Check system resources
Write-Host "`n3. Checking system resources..." -ForegroundColor Yellow
$memory = Get-WmiObject -Class Win32_OperatingSystem
$totalMemoryGB = [math]::Round($memory.TotalVisibleMemorySize / 1MB, 2)
$freeMemoryGB = [math]::Round($memory.FreePhysicalMemory / 1MB, 2)

Write-Host "Total Memory: $totalMemoryGB GB" -ForegroundColor White
Write-Host "Free Memory: $freeMemoryGB GB" -ForegroundColor White

if ($freeMemoryGB -lt 4) {
    Write-Host "⚠ Warning: Less than 4GB free memory. Consider closing other applications." -ForegroundColor Yellow
} else {
    Write-Host "✓ Sufficient memory available" -ForegroundColor Green
}

# Check disk space
$disk = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
$freeDiskGB = [math]::Round($disk.FreeSpace / 1GB, 2)
Write-Host "Free Disk Space (C:): $freeDiskGB GB" -ForegroundColor White

if ($freeDiskGB -lt 20) {
    Write-Host "⚠ Warning: Less than 20GB free disk space. Docker build may fail." -ForegroundColor Yellow
} else {
    Write-Host "✓ Sufficient disk space available" -ForegroundColor Green
}

# Provide solutions for common issues
Write-Host "`n4. Common Solutions:" -ForegroundColor Yellow
Write-Host "===================" -ForegroundColor Yellow

Write-Host "`nIf build fails with Node.js version error:" -ForegroundColor Cyan
Write-Host "- This has been fixed in the updated Dockerfile.frontend" -ForegroundColor White
Write-Host "- Run: docker-compose build --no-cache frontend" -ForegroundColor White

Write-Host "`nIf build is slow or times out:" -ForegroundColor Cyan
Write-Host "- Increase Docker Desktop memory allocation to 6GB+" -ForegroundColor White
Write-Host "- Check internet connection stability" -ForegroundColor White
Write-Host "- Run: docker system prune -f (to clear cache)" -ForegroundColor White

Write-Host "`nIf containers won't start:" -ForegroundColor Cyan
Write-Host "- Run: docker-compose down -v" -ForegroundColor White
Write-Host "- Run: docker-compose up --build -d" -ForegroundColor White

Write-Host "`nTo view detailed logs:" -ForegroundColor Cyan
Write-Host "- Backend: docker-compose logs -f backend" -ForegroundColor White
Write-Host "- Frontend: docker-compose logs -f frontend" -ForegroundColor White
Write-Host "- All services: docker-compose logs -f" -ForegroundColor White

Write-Host "`n5. Next Steps:" -ForegroundColor Yellow
Write-Host "==============" -ForegroundColor Yellow
Write-Host "If everything looks good, run:" -ForegroundColor Cyan
Write-Host "docker-compose up --build -d" -ForegroundColor White
Write-Host "`nThen access SPAWN at: http://localhost:3000" -ForegroundColor Green

Write-Host "`nFor more help, check docker-deployment-guide.md" -ForegroundColor Cyan