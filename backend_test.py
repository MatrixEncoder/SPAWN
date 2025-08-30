#!/usr/bin/env python3
"""
SPAWN Vulnerability Scanner Backend Test Suite
Tests all API endpoints, database operations, and core functionality
"""

import requests
import json
import time
import uuid
from datetime import datetime
import websocket
import threading
from typing import Dict, Any, List

class SPAWNBackendTester:
    def __init__(self, base_url: str = "https://secure-spawn.preview.emergentagent.com/api"):
        self.base_url = base_url
        self.ws_url = base_url.replace("https://", "wss://").replace("/api", "/ws")
        self.session = requests.Session()
        self.test_results = []
        self.created_scan_ids = []
        self.created_result_ids = []
        
    def log_test(self, test_name: str, success: bool, message: str = "", details: Any = None):
        """Log test results"""
        result = {
            "test": test_name,
            "success": success,
            "message": message,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status}: {test_name} - {message}")
        if details and not success:
            print(f"   Details: {details}")

    def test_root_endpoint(self):
        """Test GET /api/ endpoint"""
        try:
            response = self.session.get(f"{self.base_url}/")
            if response.status_code == 200:
                data = response.json()
                if "message" in data and "SPAWN" in data["message"]:
                    self.log_test("Root Endpoint", True, "Root endpoint accessible and returns correct message")
                    return True
                else:
                    self.log_test("Root Endpoint", False, "Root endpoint response missing expected content", data)
            else:
                self.log_test("Root Endpoint", False, f"HTTP {response.status_code}", response.text)
        except Exception as e:
            self.log_test("Root Endpoint", False, f"Connection error: {str(e)}")
        return False

    def test_modules_endpoint(self):
        """Test GET /api/modules endpoint"""
        try:
            response = self.session.get(f"{self.base_url}/modules")
            if response.status_code == 200:
                data = response.json()
                if "modules" in data and isinstance(data["modules"], list):
                    expected_modules = ["exec", "file", "sql", "xss", "csrf", "ssrf"]
                    available_modules = data["modules"]
                    
                    # Check if expected modules are present
                    missing_modules = [m for m in expected_modules if m not in available_modules]
                    if not missing_modules:
                        self.log_test("Modules Endpoint", True, f"All expected modules available. Total: {len(available_modules)}")
                        return True
                    else:
                        self.log_test("Modules Endpoint", False, f"Missing modules: {missing_modules}", available_modules)
                else:
                    self.log_test("Modules Endpoint", False, "Invalid response format", data)
            else:
                self.log_test("Modules Endpoint", False, f"HTTP {response.status_code}", response.text)
        except Exception as e:
            self.log_test("Modules Endpoint", False, f"Connection error: {str(e)}")
        return False

    def test_create_scan_configuration(self):
        """Test POST /api/scans endpoint"""
        try:
            scan_config = {
                "name": f"Test Scan {uuid.uuid4().hex[:8]}",
                "target_url": "https://example.com",
                "scope": "folder",
                "modules": ["exec", "file", "sql", "xss"],
                "depth": 3,
                "level": 1,
                "timeout": 30,
                "verify_ssl": True
            }
            
            response = self.session.post(
                f"{self.base_url}/scans",
                json=scan_config,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                data = response.json()
                if "id" in data and "name" in data:
                    self.created_scan_ids.append(data["id"])
                    self.log_test("Create Scan Config", True, f"Scan configuration created with ID: {data['id']}")
                    return data["id"]
                else:
                    self.log_test("Create Scan Config", False, "Invalid response format", data)
            else:
                self.log_test("Create Scan Config", False, f"HTTP {response.status_code}", response.text)
        except Exception as e:
            self.log_test("Create Scan Config", False, f"Request error: {str(e)}")
        return None

    def test_get_scan_configurations(self):
        """Test GET /api/scans endpoint"""
        try:
            response = self.session.get(f"{self.base_url}/scans")
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    self.log_test("Get Scan Configs", True, f"Retrieved {len(data)} scan configurations")
                    return True
                else:
                    self.log_test("Get Scan Configs", False, "Response is not a list", data)
            else:
                self.log_test("Get Scan Configs", False, f"HTTP {response.status_code}", response.text)
        except Exception as e:
            self.log_test("Get Scan Configs", False, f"Request error: {str(e)}")
        return False

    def test_get_specific_scan_configuration(self, scan_id: str):
        """Test GET /api/scans/{id} endpoint"""
        try:
            response = self.session.get(f"{self.base_url}/scans/{scan_id}")
            if response.status_code == 200:
                data = response.json()
                if "id" in data and data["id"] == scan_id:
                    self.log_test("Get Specific Scan Config", True, f"Retrieved scan config for ID: {scan_id}")
                    return True
                else:
                    self.log_test("Get Specific Scan Config", False, "ID mismatch in response", data)
            elif response.status_code == 404:
                self.log_test("Get Specific Scan Config", False, "Scan configuration not found", scan_id)
            else:
                self.log_test("Get Specific Scan Config", False, f"HTTP {response.status_code}", response.text)
        except Exception as e:
            self.log_test("Get Specific Scan Config", False, f"Request error: {str(e)}")
        return False

    def test_start_scan(self, scan_id: str):
        """Test POST /api/scans/{id}/start endpoint"""
        try:
            response = self.session.post(f"{self.base_url}/scans/{scan_id}/start")
            if response.status_code == 200:
                data = response.json()
                if "message" in data and "result_id" in data:
                    result_id = data["result_id"]
                    self.created_result_ids.append(result_id)
                    self.log_test("Start Scan", True, f"Scan started successfully. Result ID: {result_id}")
                    return result_id
                else:
                    self.log_test("Start Scan", False, "Invalid response format", data)
            elif response.status_code == 404:
                self.log_test("Start Scan", False, "Scan configuration not found", scan_id)
            elif response.status_code == 400:
                self.log_test("Start Scan", False, "Scan already running or invalid request", response.json())
            else:
                self.log_test("Start Scan", False, f"HTTP {response.status_code}", response.text)
        except Exception as e:
            self.log_test("Start Scan", False, f"Request error: {str(e)}")
        return None

    def test_stop_scan(self, scan_id: str):
        """Test POST /api/scans/{id}/stop endpoint"""
        try:
            response = self.session.post(f"{self.base_url}/scans/{scan_id}/stop")
            if response.status_code == 200:
                data = response.json()
                if "message" in data:
                    self.log_test("Stop Scan", True, "Scan stopped successfully")
                    return True
                else:
                    self.log_test("Stop Scan", False, "Invalid response format", data)
            elif response.status_code == 400:
                self.log_test("Stop Scan", False, "No active scan found", response.json())
            else:
                self.log_test("Stop Scan", False, f"HTTP {response.status_code}", response.text)
        except Exception as e:
            self.log_test("Stop Scan", False, f"Request error: {str(e)}")
        return False

    def test_get_all_results(self):
        """Test GET /api/results endpoint"""
        try:
            response = self.session.get(f"{self.base_url}/results")
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    self.log_test("Get All Results", True, f"Retrieved {len(data)} scan results")
                    return True
                else:
                    self.log_test("Get All Results", False, "Response is not a list", data)
            else:
                self.log_test("Get All Results", False, f"HTTP {response.status_code}", response.text)
        except Exception as e:
            self.log_test("Get All Results", False, f"Request error: {str(e)}")
        return False

    def test_get_specific_result(self, result_id: str):
        """Test GET /api/results/{id} endpoint"""
        try:
            response = self.session.get(f"{self.base_url}/results/{result_id}")
            if response.status_code == 200:
                data = response.json()
                if "id" in data and data["id"] == result_id:
                    self.log_test("Get Specific Result", True, f"Retrieved result for ID: {result_id}")
                    return True
                else:
                    self.log_test("Get Specific Result", False, "ID mismatch in response", data)
            elif response.status_code == 404:
                self.log_test("Get Specific Result", False, "Result not found", result_id)
            else:
                self.log_test("Get Specific Result", False, f"HTTP {response.status_code}", response.text)
        except Exception as e:
            self.log_test("Get Specific Result", False, f"Request error: {str(e)}")
        return False

    def test_export_functionality(self, result_id: str):
        """Test GET /api/results/{id}/export/{format} endpoints"""
        formats = ["json", "csv", "pdf", "html"]
        success_count = 0
        
        for format_type in formats:
            try:
                response = self.session.get(f"{self.base_url}/results/{result_id}/export/{format_type}")
                if response.status_code == 200:
                    # Check content type and basic content
                    content_type = response.headers.get('content-type', '')
                    if format_type == "json":
                        data = response.json()
                        if "scan_result" in data:
                            self.log_test(f"Export {format_type.upper()}", True, f"JSON export successful")
                            success_count += 1
                        else:
                            self.log_test(f"Export {format_type.upper()}", False, "Invalid JSON structure", data)
                    elif format_type == "csv" and "text/csv" in content_type:
                        self.log_test(f"Export {format_type.upper()}", True, f"CSV export successful")
                        success_count += 1
                    elif format_type == "pdf" and "application/pdf" in content_type:
                        self.log_test(f"Export {format_type.upper()}", True, f"PDF export successful")
                        success_count += 1
                    elif format_type == "html" and "text/html" in content_type:
                        self.log_test(f"Export {format_type.upper()}", True, f"HTML export successful")
                        success_count += 1
                    else:
                        self.log_test(f"Export {format_type.upper()}", False, f"Unexpected content type: {content_type}")
                elif response.status_code == 404:
                    self.log_test(f"Export {format_type.upper()}", False, "Result not found", result_id)
                elif response.status_code == 400:
                    self.log_test(f"Export {format_type.upper()}", False, "Unsupported format", format_type)
                else:
                    self.log_test(f"Export {format_type.upper()}", False, f"HTTP {response.status_code}", response.text)
            except Exception as e:
                self.log_test(f"Export {format_type.upper()}", False, f"Request error: {str(e)}")
        
        return success_count == len(formats)

    def test_websocket_connection(self):
        """Test WebSocket connection"""
        try:
            ws_messages = []
            
            def on_message(ws, message):
                ws_messages.append(json.loads(message))
            
            def on_error(ws, error):
                print(f"WebSocket error: {error}")
            
            def on_close(ws, close_status_code, close_msg):
                print("WebSocket connection closed")
            
            def on_open(ws):
                print("WebSocket connection opened")
                # Send a test message
                ws.send(json.dumps({"type": "test", "message": "Hello"}))
                time.sleep(2)
                ws.close()
            
            ws = websocket.WebSocketApp(
                self.ws_url,
                on_open=on_open,
                on_message=on_message,
                on_error=on_error,
                on_close=on_close
            )
            
            # Run WebSocket in a separate thread with timeout
            ws_thread = threading.Thread(target=ws.run_forever)
            ws_thread.daemon = True
            ws_thread.start()
            ws_thread.join(timeout=10)
            
            if ws_thread.is_alive():
                self.log_test("WebSocket Connection", False, "WebSocket connection timeout")
                return False
            else:
                self.log_test("WebSocket Connection", True, "WebSocket connection established and closed successfully")
                return True
                
        except Exception as e:
            self.log_test("WebSocket Connection", False, f"WebSocket error: {str(e)}")
            return False

    def test_error_handling(self):
        """Test various error scenarios"""
        error_tests = []
        
        # Test invalid scan ID
        try:
            response = self.session.get(f"{self.base_url}/scans/invalid-id")
            if response.status_code == 404:
                error_tests.append(("Invalid Scan ID", True, "Correctly returns 404"))
            else:
                error_tests.append(("Invalid Scan ID", False, f"Expected 404, got {response.status_code}"))
        except Exception as e:
            error_tests.append(("Invalid Scan ID", False, f"Request error: {str(e)}"))
        
        # Test invalid result ID
        try:
            response = self.session.get(f"{self.base_url}/results/invalid-id")
            if response.status_code == 404:
                error_tests.append(("Invalid Result ID", True, "Correctly returns 404"))
            else:
                error_tests.append(("Invalid Result ID", False, f"Expected 404, got {response.status_code}"))
        except Exception as e:
            error_tests.append(("Invalid Result ID", False, f"Request error: {str(e)}"))
        
        # Test invalid export format
        if self.created_result_ids:
            try:
                response = self.session.get(f"{self.base_url}/results/{self.created_result_ids[0]}/export/invalid")
                if response.status_code == 400:
                    error_tests.append(("Invalid Export Format", True, "Correctly returns 400"))
                else:
                    error_tests.append(("Invalid Export Format", False, f"Expected 400, got {response.status_code}"))
            except Exception as e:
                error_tests.append(("Invalid Export Format", False, f"Request error: {str(e)}"))
        
        # Test invalid scan configuration
        try:
            invalid_config = {"name": ""}  # Missing required fields
            response = self.session.post(
                f"{self.base_url}/scans",
                json=invalid_config,
                headers={"Content-Type": "application/json"}
            )
            if response.status_code in [400, 422]:
                error_tests.append(("Invalid Scan Config", True, "Correctly rejects invalid config"))
            else:
                error_tests.append(("Invalid Scan Config", False, f"Expected 400/422, got {response.status_code}"))
        except Exception as e:
            error_tests.append(("Invalid Scan Config", False, f"Request error: {str(e)}"))
        
        # Log all error handling test results
        for test_name, success, message in error_tests:
            self.log_test(f"Error Handling - {test_name}", success, message)
        
        return all(result[1] for result in error_tests)

    def run_comprehensive_test(self):
        """Run all backend tests"""
        print("🚀 Starting SPAWN Backend Comprehensive Test Suite")
        print("=" * 60)
        
        # Test basic connectivity
        if not self.test_root_endpoint():
            print("❌ Cannot connect to backend. Stopping tests.")
            return False
        
        # Test modules endpoint
        self.test_modules_endpoint()
        
        # Test scan configuration management
        scan_id = self.test_create_scan_configuration()
        self.test_get_scan_configurations()
        
        if scan_id:
            self.test_get_specific_scan_configuration(scan_id)
            
            # Test scan execution
            result_id = self.test_start_scan(scan_id)
            
            # Wait a moment for scan to initialize
            time.sleep(2)
            
            # Test stopping scan
            self.test_stop_scan(scan_id)
            
            if result_id:
                # Test result retrieval
                self.test_get_specific_result(result_id)
                
                # Test export functionality
                self.test_export_functionality(result_id)
        
        # Test results endpoint
        self.test_get_all_results()
        
        # Test WebSocket
        self.test_websocket_connection()
        
        # Test error handling
        self.test_error_handling()
        
        # Print summary
        self.print_test_summary()
        
        return self.get_overall_success()

    def print_test_summary(self):
        """Print comprehensive test summary"""
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)
        
        passed = sum(1 for result in self.test_results if result["success"])
        total = len(self.test_results)
        
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {total - passed}")
        print(f"Success Rate: {(passed/total)*100:.1f}%")
        
        print("\n📋 DETAILED RESULTS:")
        for result in self.test_results:
            status = "✅" if result["success"] else "❌"
            print(f"{status} {result['test']}: {result['message']}")
        
        if total - passed > 0:
            print("\n🔍 FAILED TESTS:")
            for result in self.test_results:
                if not result["success"]:
                    print(f"❌ {result['test']}: {result['message']}")
                    if result["details"]:
                        print(f"   Details: {result['details']}")

    def get_overall_success(self):
        """Check if all critical tests passed"""
        critical_tests = [
            "Root Endpoint",
            "Modules Endpoint", 
            "Create Scan Config",
            "Get Scan Configs"
        ]
        
        for result in self.test_results:
            if result["test"] in critical_tests and not result["success"]:
                return False
        
        return True

def main():
    """Main test execution"""
    print("🔍 SPAWN Vulnerability Scanner Backend Test Suite")
    print("Testing backend at: https://secure-spawn.preview.emergentagent.com/api")
    print()
    
    tester = SPAWNBackendTester()
    success = tester.run_comprehensive_test()
    
    if success:
        print("\n🎉 All critical backend tests passed!")
        return 0
    else:
        print("\n💥 Some critical backend tests failed!")
        return 1

if __name__ == "__main__":
    exit(main())