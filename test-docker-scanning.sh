#!/bin/bash

echo "🐳 SPAWN Docker Scanning Test Script"
echo "======================================"

# Function to check if Docker containers are running
check_containers() {
    echo "📋 Checking Docker containers..."
    
    # Check if containers are running
    if ! docker compose ps | grep -q "running"; then
        echo "❌ Docker containers are not running. Please start them first:"
        echo "   docker compose up --build"
        exit 1
    fi
    
    echo "✅ Docker containers are running"
    
    # Show container status
    echo ""
    echo "📊 Container Status:"
    docker compose ps
    echo ""
}

# Function to test backend API connectivity
test_backend_api() {
    echo "🔗 Testing Backend API connectivity..."
    
    # Test root API endpoint
    if curl -s -f http://localhost:8001/api/ > /dev/null; then
        echo "✅ Backend API is accessible"
    else
        echo "❌ Backend API is not accessible"
        echo "   Check if backend container is running and healthy"
        return 1
    fi
    
    # Test Wapiti modules endpoint
    echo "📋 Testing Wapiti modules endpoint..."
    modules_response=$(curl -s http://localhost:8001/api/modules)
    if echo "$modules_response" | grep -q "exec"; then
        module_count=$(echo "$modules_response" | jq '. | length' 2>/dev/null || echo "unknown")
        echo "✅ Wapiti modules loaded successfully ($module_count modules)"
    else
        echo "❌ Wapiti modules endpoint failed"
        echo "   Response: $modules_response"
        return 1
    fi
}

# Function to test scan creation
test_scan_creation() {
    echo "🎯 Testing scan creation..."
    
    # Create a test scan configuration
    scan_config='{
        "name": "Docker Test Scan",
        "target_url": "http://testphp.vulnweb.com",
        "scan_type": "quick",
        "scope": "folder",
        "depth": 2,
        "level": 1,
        "timeout": 60,
        "verify_ssl": false
    }'
    
    # Create scan
    create_response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$scan_config" \
        http://localhost:8001/api/scans)
    
    if echo "$create_response" | grep -q '"id"'; then
        scan_id=$(echo "$create_response" | jq -r '.id' 2>/dev/null)
        echo "✅ Scan created successfully (ID: $scan_id)"
        echo "$scan_id" > /tmp/docker_test_scan_id
        return 0
    else
        echo "❌ Scan creation failed"
        echo "   Response: $create_response"
        return 1
    fi
}

# Function to test scan execution
test_scan_execution() {
    echo "🚀 Testing scan execution..."
    
    # Get scan ID from previous test
    if [ ! -f /tmp/docker_test_scan_id ]; then
        echo "❌ No scan ID found from creation test"
        return 1
    fi
    
    scan_id=$(cat /tmp/docker_test_scan_id)
    
    # Start scan
    start_response=$(curl -s -X POST http://localhost:8001/api/scans/$scan_id/start)
    
    if echo "$start_response" | grep -q '"result_id"'; then
        result_id=$(echo "$start_response" | jq -r '.result_id' 2>/dev/null)
        echo "✅ Scan started successfully (Result ID: $result_id)"
        
        # Monitor scan for a short time to verify it's running
        echo "📊 Monitoring scan progress for 30 seconds..."
        for i in {1..6}; do
            sleep 5
            progress_response=$(curl -s http://localhost:8001/api/results/$result_id)
            status=$(echo "$progress_response" | jq -r '.status' 2>/dev/null)
            progress=$(echo "$progress_response" | jq -r '.progress' 2>/dev/null)
            error_message=$(echo "$progress_response" | jq -r '.error_message' 2>/dev/null)
            
            echo "   Progress: $progress% - Status: $status"
            
            # Check for Wapiti path errors
            if [ "$error_message" != "null" ] && [ "$error_message" != "" ]; then
                if echo "$error_message" | grep -qi "not found\|no such file"; then
                    echo "❌ Wapiti path error detected: $error_message"
                    return 1
                fi
            fi
            
            # If scan completes or shows progress, it's working
            if [ "$status" = "completed" ] || [ "$progress" != "0" ] && [ "$progress" != "null" ]; then
                echo "✅ Scan is executing properly (no path errors detected)"
                break
            fi
        done
        
        return 0
    else
        echo "❌ Scan start failed"
        echo "   Response: $start_response"
        return 1
    fi
}

# Function to test Wapiti command in container
test_wapiti_command() {
    echo "🔍 Testing Wapiti command in Docker container..."
    
    # Execute wapiti command inside the backend container
    wapiti_test=$(docker exec spawn_backend wapiti --version 2>&1)
    
    if echo "$wapiti_test" | grep -q "Wapiti"; then
        echo "✅ Wapiti command is available in Docker container"
        echo "   Version: $(echo "$wapiti_test" | head -1)"
    else
        echo "❌ Wapiti command not found in Docker container"
        echo "   Output: $wapiti_test"
        return 1
    fi
}

# Function to cleanup test resources
cleanup() {
    echo "🧹 Cleaning up test resources..."
    if [ -f /tmp/docker_test_scan_id ]; then
        rm /tmp/docker_test_scan_id
    fi
    echo "✅ Cleanup completed"
}

# Main test execution
main() {
    echo "Starting SPAWN Docker scanning tests..."
    echo ""
    
    # Check if docker compose is available
    if ! command -v docker &> /dev/null; then
        echo "❌ Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! command -v "docker compose" &> /dev/null; then
        echo "❌ Docker Compose is not available"
        exit 1
    fi
    
    # Run tests
    test_failed=0
    
    check_containers || test_failed=1
    
    if [ $test_failed -eq 0 ]; then
        test_wapiti_command || test_failed=1
    fi
    
    if [ $test_failed -eq 0 ]; then
        test_backend_api || test_failed=1
    fi
    
    if [ $test_failed -eq 0 ]; then
        test_scan_creation || test_failed=1
    fi
    
    if [ $test_failed -eq 0 ]; then
        test_scan_execution || test_failed=1
    fi
    
    cleanup
    
    echo ""
    echo "======================================"
    if [ $test_failed -eq 0 ]; then
        echo "🎉 All Docker scanning tests PASSED!"
        echo "   Wapiti scanning should work correctly in Docker"
        echo ""
        echo "Next steps:"
        echo "1. Access frontend: http://localhost:3000"
        echo "2. Create vulnerability scans"
        echo "3. Monitor real-time progress"
        echo "4. Export professional reports"
    else
        echo "❌ Some Docker scanning tests FAILED"
        echo "   Please check the errors above and verify your Docker setup"
        echo ""
        echo "Troubleshooting:"
        echo "1. Check container logs: docker compose logs backend"
        echo "2. Verify all containers are healthy: docker compose ps"
        echo "3. Rebuild containers: docker compose up --build"
    fi
    echo "======================================"
}

# Run main function
main "$@"