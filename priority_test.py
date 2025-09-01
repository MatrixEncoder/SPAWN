#!/usr/bin/env python3
"""
SPAWN Priority Tests - Focus on Review Request Issues
Tests the specific issues mentioned in the review request
"""

import requests
import json
import time
from datetime import datetime

class SPAWNPriorityTester:
    def __init__(self):
        self.base_url = "https://scan-fixer.preview.emergentagent.com/api"
        self.session = requests.Session()
        self.results = []
        
    def log_result(self, test_name: str, success: bool, message: str, details=None):
        """Log test results"""
        result = {
            "test": test_name,
            "success": success,
            "message": message,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        self.results.append(result)
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status}: {test_name}")
        print(f"   {message}")
        if details and not success:
            print(f"   Details: {details}")
        print()

    def test_scan_presets_improved(self):
        """PRIORITY TEST 1: Verify improved scan presets"""
        print("🎯 PRIORITY TEST 1: Scan Configuration Improvements")
        print("=" * 50)
        
        try:
            response = self.session.get(f"{self.base_url}/scan-presets", timeout=10)
            if response.status_code == 200:
                data = response.json()
                presets = data.get("presets", {})
                
                if "quick" in presets:
                    quick = presets["quick"]
                    
                    # Check improvements mentioned in review request
                    improvements = []
                    issues = []
                    
                    # Domain scope (not folder)
                    if quick.get("scope") == "domain":
                        improvements.append("✓ Domain scope")
                    else:
                        issues.append(f"Scope is {quick.get('scope')}, should be 'domain'")
                    
                    # Better depth (should be 3+)
                    depth = quick.get("depth", 0)
                    if depth >= 3:
                        improvements.append(f"✓ Depth: {depth}")
                    else:
                        issues.append(f"Depth is {depth}, should be >= 3")
                    
                    # Better level (should be 2+)
                    level = quick.get("level", 0)
                    if level >= 2:
                        improvements.append(f"✓ Level: {level}")
                    else:
                        issues.append(f"Level is {level}, should be >= 2")
                    
                    # More modules (should be 6+)
                    modules = quick.get("modules", [])
                    if len(modules) >= 6:
                        improvements.append(f"✓ Modules: {len(modules)} ({', '.join(modules[:3])}...)")
                    else:
                        issues.append(f"Only {len(modules)} modules, should be >= 6")
                    
                    if not issues:
                        self.log_result("Scan Presets Improved", True, 
                                      f"Quick scan preset has all improvements: {'; '.join(improvements)}")
                        return True
                    else:
                        self.log_result("Scan Presets Improved", False, 
                                      f"Issues found: {'; '.join(issues)}", quick)
                else:
                    self.log_result("Scan Presets Improved", False, "Quick preset not found", presets)
            else:
                self.log_result("Scan Presets Improved", False, f"HTTP {response.status_code}", response.text)
        except Exception as e:
            self.log_result("Scan Presets Improved", False, f"Request error: {str(e)}")
        
        return False

    def test_export_functionality(self):
        """PRIORITY TEST 2: Test export functionality with existing scan"""
        print("🎯 PRIORITY TEST 2: Export Functionality")
        print("=" * 50)
        
        # Test with the existing scan result mentioned in review request
        result_id = "581a87f8-acc7-49b5-959d-4a9461e49dbf"
        
        try:
            # First check if the result exists
            response = self.session.get(f"{self.base_url}/results/{result_id}", timeout=10)
            if response.status_code == 200:
                result_data = response.json()
                self.log_result("Existing Scan Result", True, 
                              f"Found existing scan: status={result_data.get('status')}, "
                              f"vulnerabilities={len(result_data.get('vulnerabilities', []))}")
                
                # Test all export formats
                formats = ["json", "csv", "pdf", "html"]
                export_results = []
                
                for format_type in formats:
                    try:
                        export_response = self.session.get(
                            f"{self.base_url}/results/{result_id}/export/{format_type}", 
                            timeout=30
                        )
                        
                        if export_response.status_code == 200:
                            content_type = export_response.headers.get('content-type', '')
                            content_length = len(export_response.content)
                            
                            # Validate content
                            valid = False
                            if format_type == "json":
                                try:
                                    json_data = export_response.json()
                                    valid = "scan_result" in json_data
                                except:
                                    valid = False
                            elif format_type == "csv":
                                valid = content_length > 100 and ("csv" in content_type or "text" in content_type)
                            elif format_type == "pdf":
                                valid = content_length > 1000 and "pdf" in content_type
                            elif format_type == "html":
                                valid = content_length > 200 and "html" in content_type
                            
                            if valid:
                                export_results.append(f"✓ {format_type.upper()}: {content_length} bytes")
                                self.log_result(f"Export {format_type.upper()}", True, 
                                              f"Export successful ({content_length} bytes, {content_type})")
                            else:
                                export_results.append(f"✗ {format_type.upper()}: Invalid content")
                                self.log_result(f"Export {format_type.upper()}", False, 
                                              f"Invalid content ({content_length} bytes, {content_type})")
                        else:
                            export_results.append(f"✗ {format_type.upper()}: HTTP {export_response.status_code}")
                            self.log_result(f"Export {format_type.upper()}", False, 
                                          f"HTTP {export_response.status_code}")
                    except Exception as e:
                        export_results.append(f"✗ {format_type.upper()}: Error")
                        self.log_result(f"Export {format_type.upper()}", False, f"Error: {str(e)}")
                
                # Summary
                successful_exports = len([r for r in export_results if r.startswith("✓")])
                if successful_exports == len(formats):
                    self.log_result("All Export Formats", True, f"All {len(formats)} export formats working")
                    return True
                else:
                    self.log_result("All Export Formats", False, 
                                  f"Only {successful_exports}/{len(formats)} formats working")
                
            elif response.status_code == 404:
                self.log_result("Existing Scan Result", False, 
                              f"Existing scan result {result_id} not found - may have been cleaned up")
                
                # Try to find any completed scan result
                all_results_response = self.session.get(f"{self.base_url}/results", timeout=10)
                if all_results_response.status_code == 200:
                    all_results = all_results_response.json()
                    completed_results = [r for r in all_results if r.get("status") == "completed"]
                    
                    if completed_results:
                        test_result = completed_results[0]
                        self.log_result("Alternative Scan Result", True, 
                                      f"Using alternative result: {test_result['id']}")
                        # Recursively test with alternative result
                        return self.test_export_with_result(test_result['id'])
                    else:
                        self.log_result("Alternative Scan Result", False, "No completed scan results found")
            else:
                self.log_result("Existing Scan Result", False, f"HTTP {response.status_code}", response.text)
                
        except Exception as e:
            self.log_result("Export Functionality", False, f"Request error: {str(e)}")
        
        return False

    def test_export_with_result(self, result_id: str):
        """Helper method to test export with a specific result ID"""
        formats = ["json", "csv", "pdf", "html"]
        successful_exports = 0
        
        for format_type in formats:
            try:
                export_response = self.session.get(
                    f"{self.base_url}/results/{result_id}/export/{format_type}", 
                    timeout=30
                )
                
                if export_response.status_code == 200:
                    content_length = len(export_response.content)
                    if content_length > 50:  # Basic content check
                        successful_exports += 1
                        self.log_result(f"Export {format_type.upper()}", True, 
                                      f"Export successful ({content_length} bytes)")
                    else:
                        self.log_result(f"Export {format_type.upper()}", False, 
                                      f"Content too small ({content_length} bytes)")
                else:
                    self.log_result(f"Export {format_type.upper()}", False, 
                                  f"HTTP {export_response.status_code}")
            except Exception as e:
                self.log_result(f"Export {format_type.upper()}", False, f"Error: {str(e)}")
        
        return successful_exports == len(formats)

    def test_vulnerable_site_detection(self):
        """PRIORITY TEST 3: Test authentic vulnerability detection"""
        print("🎯 PRIORITY TEST 3: Authentic Vulnerability Detection")
        print("=" * 50)
        
        try:
            # Create a scan configuration for a vulnerable test site
            scan_config = {
                "name": "Vulnerability Detection Test",
                "target_url": "http://testphp.vulnweb.com/",
                "scan_type": "quick",
                "scope": "domain",
                "modules": ["exec", "file", "sql", "xss", "csrf", "ssrf"],
                "depth": 3,
                "level": 2,
                "timeout": 45,
                "max_scan_time": 180,  # 3 minutes max for testing
                "verify_ssl": False
            }
            
            # Create scan configuration
            response = self.session.post(
                f"{self.base_url}/scans",
                json=scan_config,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if response.status_code == 200:
                scan_data = response.json()
                scan_id = scan_data["id"]
                
                self.log_result("Vulnerable Site Scan Config", True, 
                              f"Created scan config for testphp.vulnweb.com: {scan_id}")
                
                # Start the scan
                start_response = self.session.post(f"{self.base_url}/scans/{scan_id}/start", timeout=10)
                if start_response.status_code == 200:
                    start_data = start_response.json()
                    result_id = start_data["result_id"]
                    
                    self.log_result("Vulnerable Site Scan Start", True, 
                                  f"Scan started, monitoring progress: {result_id}")
                    
                    # Monitor for progress and completion (max 3 minutes)
                    max_wait = 180
                    start_time = time.time()
                    last_progress = 0
                    progress_updates = 0
                    
                    while time.time() - start_time < max_wait:
                        try:
                            result_response = self.session.get(f"{self.base_url}/results/{result_id}", timeout=10)
                            if result_response.status_code == 200:
                                result_data = result_response.json()
                                current_progress = result_data.get("progress", 0)
                                status = result_data.get("status", "unknown")
                                
                                # Track progress updates
                                if current_progress > last_progress:
                                    progress_updates += 1
                                    last_progress = current_progress
                                    print(f"   Progress: {current_progress}% - Status: {status}")
                                
                                if status == "completed":
                                    vulnerabilities = result_data.get("vulnerabilities", [])
                                    vuln_count = len(vulnerabilities)
                                    
                                    # Test real-time progress tracking
                                    if progress_updates > 0:
                                        self.log_result("Real-time Progress Tracking", True, 
                                                      f"Received {progress_updates} progress updates (final: {current_progress}%)")
                                    else:
                                        self.log_result("Real-time Progress Tracking", False, 
                                                      "No progress updates received during scan")
                                    
                                    # Test vulnerability detection
                                    if vuln_count > 0:
                                        severity_counts = {}
                                        for vuln in vulnerabilities:
                                            severity = vuln.get("severity", "unknown")
                                            severity_counts[severity] = severity_counts.get(severity, 0) + 1
                                        
                                        severity_summary = ", ".join([f"{k}: {v}" for k, v in severity_counts.items()])
                                        self.log_result("Authentic Vulnerability Detection", True, 
                                                      f"Found {vuln_count} vulnerabilities ({severity_summary})")
                                        return True
                                    else:
                                        self.log_result("Authentic Vulnerability Detection", False, 
                                                      "No vulnerabilities found on known vulnerable site")
                                        return False
                                        
                                elif status == "failed":
                                    error_msg = result_data.get("error_message", "Unknown error")
                                    self.log_result("Vulnerable Site Scan", False, f"Scan failed: {error_msg}")
                                    return False
                            
                            time.sleep(5)  # Wait 5 seconds between checks
                            
                        except Exception as e:
                            print(f"   Error checking progress: {e}")
                            time.sleep(5)
                    
                    # Timeout reached
                    self.log_result("Vulnerable Site Scan Timeout", False, 
                                  f"Scan did not complete within {max_wait} seconds")
                    
                else:
                    self.log_result("Vulnerable Site Scan Start", False, 
                                  f"Failed to start scan: {start_response.status_code}")
            else:
                self.log_result("Vulnerable Site Scan Config", False, 
                              f"Failed to create scan config: {response.status_code}")
                
        except Exception as e:
            self.log_result("Vulnerable Site Detection", False, f"Request error: {str(e)}")
        
        return False

    def run_priority_tests(self):
        """Run all priority tests"""
        print("🎯 SPAWN Priority Tests - Review Request Focus")
        print("=" * 60)
        print("Testing critical user-reported issues:")
        print("1. Wapiti authentic scanning with improved configuration")
        print("2. Real-time progress tracking")
        print("3. Export functionality (PDF, CSV, HTML, JSON)")
        print("4. Scan configuration improvements")
        print()
        
        # Test 1: Improved scan presets
        test1_success = self.test_scan_presets_improved()
        
        # Test 2: Export functionality
        test2_success = self.test_export_functionality()
        
        # Test 3 & 4: Vulnerability detection and progress tracking
        test3_success = self.test_vulnerable_site_detection()
        
        # Summary
        print("\n" + "=" * 60)
        print("📊 PRIORITY TESTS SUMMARY")
        print("=" * 60)
        
        passed = sum(1 for result in self.results if result["success"])
        total = len(self.results)
        
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {total - passed}")
        print(f"Success Rate: {(passed/total)*100:.1f}%")
        
        print("\n📋 KEY FINDINGS:")
        critical_tests = ["Scan Presets Improved", "All Export Formats", "Authentic Vulnerability Detection", "Real-time Progress Tracking"]
        
        for test_name in critical_tests:
            result = next((r for r in self.results if r["test"] == test_name), None)
            if result:
                status = "✅" if result["success"] else "❌"
                print(f"{status} {test_name}: {result['message']}")
        
        # Overall assessment
        critical_passed = sum(1 for test_name in critical_tests 
                            for result in self.results 
                            if result["test"] == test_name and result["success"])
        
        if critical_passed >= 3:  # At least 3 out of 4 critical tests
            print(f"\n🎉 Priority tests mostly successful ({critical_passed}/4 critical tests passed)")
            return True
        else:
            print(f"\n💥 Priority tests need attention ({critical_passed}/4 critical tests passed)")
            return False

def main():
    """Main execution"""
    tester = SPAWNPriorityTester()
    success = tester.run_priority_tests()
    return 0 if success else 1

if __name__ == "__main__":
    exit(main())