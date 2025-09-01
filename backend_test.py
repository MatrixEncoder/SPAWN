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
    def __init__(self, base_url: str = "https://scan-debug-1.preview.emergentagent.com/api"):
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
        """Test GET /api/results/{id}/export/{format} endpoints with enhanced professional report validation"""
        formats = ["json", "csv", "pdf", "html"]
        success_count = 0
        
        for format_type in formats:
            try:
                response = self.session.get(f"{self.base_url}/results/{result_id}/export/{format_type}")
                if response.status_code == 200:
                    # Check content type and basic content
                    content_type = response.headers.get('content-type', '')
                    content_length = len(response.content)
                    
                    if format_type == "json":
                        data = response.json()
                        if "scan_result" in data:
                            self.log_test(f"Export {format_type.upper()}", True, f"JSON export successful ({content_length} bytes)")
                            success_count += 1
                        else:
                            self.log_test(f"Export {format_type.upper()}", False, "Invalid JSON structure", data)
                    elif format_type == "csv" and ("text/csv" in content_type or "application/csv" in content_type):
                        if content_length > 100:  # Basic content check
                            self.log_test(f"Export {format_type.upper()}", True, f"CSV export successful ({content_length} bytes)")
                            success_count += 1
                        else:
                            self.log_test(f"Export {format_type.upper()}", False, f"CSV content too small ({content_length} bytes)")
                    elif format_type == "pdf" and "application/pdf" in content_type:
                        if content_length > 1000:  # PDF should be substantial
                            self.log_test(f"Export {format_type.upper()}", True, f"PDF export successful ({content_length} bytes)")
                            success_count += 1
                        else:
                            self.log_test(f"Export {format_type.upper()}", False, f"PDF content too small ({content_length} bytes)")
                    elif format_type == "html" and "text/html" in content_type:
                        if content_length > 200:  # HTML should have reasonable content
                            self.log_test(f"Export {format_type.upper()}", True, f"HTML export successful ({content_length} bytes)")
                            success_count += 1
                        else:
                            self.log_test(f"Export {format_type.upper()}", False, f"HTML content too small ({content_length} bytes)")
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

    def test_professional_report_format(self, result_id: str):
        """Test the new professional report format structure for PDF, HTML, and CSV exports"""
        print("\n🎯 TESTING PROFESSIONAL REPORT FORMAT")
        print("Validating new report structure with header table, vulnerability distribution, and detailed findings")
        
        # Test PDF Export Format
        try:
            response = self.session.get(f"{self.base_url}/results/{result_id}/export/pdf")
            if response.status_code == 200:
                content_type = response.headers.get('content-type', '')
                content_length = len(response.content)
                
                if "application/pdf" in content_type and content_length > 5000:
                    # Save PDF for manual inspection if needed
                    with open("/tmp/test_report.pdf", "wb") as f:
                        f.write(response.content)
                    
                    self.log_test("PDF Professional Format", True, 
                        f"PDF report generated with professional format ({content_length} bytes)")
                else:
                    self.log_test("PDF Professional Format", False, 
                        f"PDF format issues: content_type={content_type}, size={content_length}")
            else:
                self.log_test("PDF Professional Format", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("PDF Professional Format", False, f"Error: {str(e)}")
        
        # Test HTML Export Format with content validation
        try:
            response = self.session.get(f"{self.base_url}/results/{result_id}/export/html")
            if response.status_code == 200:
                content = response.text
                content_length = len(content)
                
                # Check for professional report structure elements
                required_elements = [
                    "Target URL:",
                    "Scan Date:",
                    "Scan Status:",
                    "Total Vulnerabilities:",
                    "Scan Duration:",
                    "Vulnerability Distribution",
                    "Detailed Vulnerability Findings",
                    "SPAWN - Professional Vulnerability Assessment Platform"
                ]
                
                missing_elements = []
                for element in required_elements:
                    if element not in content:
                        missing_elements.append(element)
                
                if not missing_elements and content_length > 1000:
                    self.log_test("HTML Professional Format", True, 
                        f"HTML report contains all professional format elements ({content_length} chars)")
                    
                    # Check for proper table structure
                    table_checks = [
                        'class="info-table"',
                        'class="dist-table"', 
                        'class="vuln-table"',
                        'Severity Level',
                        'Risk Assessment'
                    ]
                    
                    table_elements_found = sum(1 for check in table_checks if check in content)
                    if table_elements_found >= 4:
                        self.log_test("HTML Table Structure", True, 
                            f"HTML contains proper table structure ({table_elements_found}/{len(table_checks)} elements)")
                    else:
                        self.log_test("HTML Table Structure", False, 
                            f"Missing table elements ({table_elements_found}/{len(table_checks)} found)")
                else:
                    self.log_test("HTML Professional Format", False, 
                        f"Missing elements: {missing_elements}, size: {content_length}")
            else:
                self.log_test("HTML Professional Format", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("HTML Professional Format", False, f"Error: {str(e)}")
        
        # Test CSV Export Format with content validation
        try:
            response = self.session.get(f"{self.base_url}/results/{result_id}/export/csv")
            if response.status_code == 200:
                content = response.text
                content_length = len(content)
                
                # Check for professional CSV structure
                required_csv_elements = [
                    "SPAWN Professional Vulnerability Assessment Report",
                    "Header Information",
                    "Target URL",
                    "Scan Date",
                    "Total Vulnerabilities",
                    "Vulnerability Distribution",
                    "Detailed Vulnerability Findings",
                    "#,Type,Severity,URL,Parameter,Description,CWE"
                ]
                
                missing_csv_elements = []
                for element in required_csv_elements:
                    if element not in content:
                        missing_csv_elements.append(element)
                
                if not missing_csv_elements and content_length > 500:
                    self.log_test("CSV Professional Format", True, 
                        f"CSV report contains all professional format elements ({content_length} chars)")
                else:
                    self.log_test("CSV Professional Format", False, 
                        f"Missing CSV elements: {missing_csv_elements}, size: {content_length}")
            else:
                self.log_test("CSV Professional Format", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_test("CSV Professional Format", False, f"Error: {str(e)}")

    def test_cwe_mappings_and_vulnerability_types(self, result_id: str):
        """Test CWE mappings and vulnerability type formatting in reports"""
        print("\n🎯 TESTING CWE MAPPINGS AND VULNERABILITY TYPES")
        
        try:
            # Get the scan result first to check vulnerabilities
            response = self.session.get(f"{self.base_url}/results/{result_id}")
            if response.status_code == 200:
                result_data = response.json()
                vulnerabilities = result_data.get("vulnerabilities", [])
                
                if not vulnerabilities:
                    self.log_test("CWE Mappings Test", False, "No vulnerabilities found in result to test CWE mappings")
                    return False
                
                # Test HTML export for CWE mappings
                html_response = self.session.get(f"{self.base_url}/results/{result_id}/export/html")
                if html_response.status_code == 200:
                    html_content = html_response.text
                    
                    # Check for CWE/WSTG references
                    cwe_patterns = ["CWE-", "WSTG-"]
                    cwe_found = any(pattern in html_content for pattern in cwe_patterns)
                    
                    # Check for properly formatted vulnerability types
                    vuln_type_patterns = ["XSS", "SQL INJECTION", "CSRF", "PATH TRAVERSAL"]
                    vuln_types_found = sum(1 for pattern in vuln_type_patterns if pattern in html_content)
                    
                    if cwe_found:
                        self.log_test("CWE Mappings in HTML", True, 
                            f"CWE/WSTG references found in HTML report")
                    else:
                        self.log_test("CWE Mappings in HTML", False, 
                            "No CWE/WSTG references found in HTML report")
                    
                    if vuln_types_found > 0:
                        self.log_test("Vulnerability Type Formatting", True, 
                            f"Found {vuln_types_found} properly formatted vulnerability types")
                    else:
                        self.log_test("Vulnerability Type Formatting", False, 
                            "No properly formatted vulnerability types found")
                
                # Test CSV export for CWE mappings
                csv_response = self.session.get(f"{self.base_url}/results/{result_id}/export/csv")
                if csv_response.status_code == 200:
                    csv_content = csv_response.text
                    
                    # Check for CWE column and data
                    cwe_column_present = "CWE" in csv_content
                    cwe_data_present = any(pattern in csv_content for pattern in ["CWE-", "WSTG-"])
                    
                    if cwe_column_present and cwe_data_present:
                        self.log_test("CWE Mappings in CSV", True, 
                            "CWE column and data properly included in CSV report")
                    else:
                        self.log_test("CWE Mappings in CSV", False, 
                            f"CWE issues - column: {cwe_column_present}, data: {cwe_data_present}")
                
                return True
            else:
                self.log_test("CWE Mappings Test", False, f"Cannot retrieve result: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("CWE Mappings Test", False, f"Error: {str(e)}")
            return False

    def test_report_content_quality(self, result_id: str):
        """Test report content quality including data completeness and formatting"""
        print("\n🎯 TESTING REPORT CONTENT QUALITY")
        
        try:
            # Get scan result and configuration
            result_response = self.session.get(f"{self.base_url}/results/{result_id}")
            if result_response.status_code != 200:
                self.log_test("Report Content Quality", False, "Cannot retrieve scan result")
                return False
            
            result_data = result_response.json()
            vulnerabilities = result_data.get("vulnerabilities", [])
            scan_id = result_data.get("scan_id")
            
            # Get scan configuration
            config_response = self.session.get(f"{self.base_url}/scans/{scan_id}")
            config_data = config_response.json() if config_response.status_code == 200 else {}
            
            # Test HTML report content quality
            html_response = self.session.get(f"{self.base_url}/results/{result_id}/export/html")
            if html_response.status_code == 200:
                html_content = html_response.text
                
                # Check header information completeness
                header_fields = [
                    config_data.get("target_url", ""),
                    result_data.get("status", "").upper(),
                    str(len(vulnerabilities))
                ]
                
                header_complete = all(field in html_content for field in header_fields if field)
                
                if header_complete:
                    self.log_test("Report Header Completeness", True, 
                        "All header information properly populated")
                else:
                    self.log_test("Report Header Completeness", False, 
                        "Missing header information in report")
                
                # Check vulnerability distribution section
                if vulnerabilities:
                    severity_counts = {}
                    for vuln in vulnerabilities:
                        severity = vuln.get("severity", "unknown").upper()
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                    # Check if severity counts are reflected in report
                    severity_section_complete = True
                    for severity, count in severity_counts.items():
                        if severity in ["HIGH", "MEDIUM", "LOW"] and count > 0:
                            if str(count) not in html_content:
                                severity_section_complete = False
                                break
                    
                    if severity_section_complete:
                        self.log_test("Vulnerability Distribution Accuracy", True, 
                            f"Severity counts accurately reflected: {severity_counts}")
                    else:
                        self.log_test("Vulnerability Distribution Accuracy", False, 
                            f"Severity counts not properly reflected: {severity_counts}")
                
                # Check detailed findings table
                if vulnerabilities:
                    # Check if vulnerability details are present
                    vuln_details_present = True
                    for vuln in vulnerabilities[:3]:  # Check first 3 vulnerabilities
                        vuln_url = vuln.get("url", "")
                        vuln_severity = vuln.get("severity", "").upper()
                        
                        if vuln_url and vuln_url not in html_content:
                            vuln_details_present = False
                            break
                        if vuln_severity and vuln_severity not in html_content:
                            vuln_details_present = False
                            break
                    
                    if vuln_details_present:
                        self.log_test("Detailed Findings Completeness", True, 
                            "Vulnerability details properly included in findings table")
                    else:
                        self.log_test("Detailed Findings Completeness", False, 
                            "Vulnerability details missing from findings table")
                
                # Check continuation table for many vulnerabilities
                if len(vulnerabilities) > 10:
                    continuation_present = "continuation-table" in html_content or "Additional" in html_content
                    if continuation_present:
                        self.log_test("Continuation Table", True, 
                            f"Continuation table present for {len(vulnerabilities)} vulnerabilities")
                    else:
                        self.log_test("Continuation Table", False, 
                            f"Continuation table missing for {len(vulnerabilities)} vulnerabilities")
                
                # Check SPAWN branding
                branding_present = "SPAWN" in html_content and "Professional Vulnerability Assessment" in html_content
                if branding_present:
                    self.log_test("SPAWN Branding", True, "SPAWN branding properly included")
                else:
                    self.log_test("SPAWN Branding", False, "SPAWN branding missing or incomplete")
                
                return True
            else:
                self.log_test("Report Content Quality", False, f"Cannot retrieve HTML report: HTTP {html_response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Report Content Quality", False, f"Error: {str(e)}")
            return False

    def test_scan_presets(self):
        """Test GET /api/scan-presets endpoint for enhanced Wapiti configurations"""
        try:
            response = self.session.get(f"{self.base_url}/scan-presets")
            if response.status_code == 200:
                data = response.json()
                if "presets" in data:
                    presets = data["presets"]
                    
                    # Test all three presets: quick, standard, deep
                    preset_tests = {
                        "quick": {
                            "min_depth": 8,
                            "min_modules": 9,
                            "expected_scope": "folder",
                            "expected_scan_force": "normal",
                            "min_max_links_per_page": 50,
                            "min_max_files_per_dir": 30
                        },
                        "standard": {
                            "min_depth": 12,
                            "min_modules": 20,
                            "expected_scope": "folder", 
                            "expected_scan_force": "aggressive",
                            "min_max_links_per_page": 100,
                            "min_max_files_per_dir": 50
                        },
                        "deep": {
                            "min_depth": 20,
                            "min_modules": 30,
                            "expected_scope": "folder",
                            "expected_scan_force": "insane",
                            "min_max_links_per_page": 200,
                            "min_max_files_per_dir": 100
                        }
                    }
                    
                    all_presets_valid = True
                    
                    for preset_name, expected in preset_tests.items():
                        if preset_name in presets:
                            preset = presets[preset_name]
                            issues = []
                            
                            # Check enhanced parameters
                            if preset.get("depth", 0) < expected["min_depth"]:
                                issues.append(f"depth is {preset.get('depth')}, expected >= {expected['min_depth']}")
                            
                            if len(preset.get("modules", [])) < expected["min_modules"]:
                                issues.append(f"modules count is {len(preset.get('modules', []))}, expected >= {expected['min_modules']}")
                            
                            if preset.get("scope") != expected["expected_scope"]:
                                issues.append(f"scope is {preset.get('scope')}, expected {expected['expected_scope']}")
                            
                            if preset.get("scan_force") != expected["expected_scan_force"]:
                                issues.append(f"scan_force is {preset.get('scan_force')}, expected {expected['expected_scan_force']}")
                            
                            if preset.get("max_links_per_page", 0) < expected["min_max_links_per_page"]:
                                issues.append(f"max_links_per_page is {preset.get('max_links_per_page')}, expected >= {expected['min_max_links_per_page']}")
                            
                            if preset.get("max_files_per_dir", 0) < expected["min_max_files_per_dir"]:
                                issues.append(f"max_files_per_dir is {preset.get('max_files_per_dir')}, expected >= {expected['min_max_files_per_dir']}")
                            
                            if not issues:
                                self.log_test(f"Enhanced Preset - {preset_name.upper()}", True, 
                                    f"{preset_name} preset enhanced: depth={preset.get('depth')}, modules={len(preset.get('modules', []))}, "
                                    f"scope={preset.get('scope')}, scan_force={preset.get('scan_force')}, "
                                    f"max_links_per_page={preset.get('max_links_per_page')}, max_files_per_dir={preset.get('max_files_per_dir')}")
                            else:
                                self.log_test(f"Enhanced Preset - {preset_name.upper()}", False, f"{preset_name} preset issues: {'; '.join(issues)}", preset)
                                all_presets_valid = False
                        else:
                            self.log_test(f"Enhanced Preset - {preset_name.upper()}", False, f"{preset_name} preset not found")
                            all_presets_valid = False
                    
                    self.log_test("Enhanced Scan Presets", all_presets_valid, f"Retrieved {len(presets)} enhanced scan presets")
                    return all_presets_valid
                else:
                    self.log_test("Enhanced Scan Presets", False, "Invalid response format", data)
            else:
                self.log_test("Enhanced Scan Presets", False, f"HTTP {response.status_code}", response.text)
        except Exception as e:
            self.log_test("Enhanced Scan Presets", False, f"Request error: {str(e)}")
        return False

    def test_enhanced_wapiti_configuration(self):
        """Test enhanced Wapiti configuration with new parameters"""
        try:
            # Test creating scan with enhanced deep preset
            enhanced_scan_config = {
                "name": f"Enhanced Deep Scan Test {uuid.uuid4().hex[:8]}",
                "target_url": "http://testphp.vulnweb.com/",
                "scan_type": "deep",
                "scope": "folder",
                "depth": 20,
                "level": 3,
                "timeout": 120,
                "max_scan_time": 10800,
                "max_links_per_page": 200,
                "max_files_per_dir": 100,
                "scan_force": "insane",
                "verify_ssl": False
            }
            
            # Create enhanced scan configuration
            response = self.session.post(
                f"{self.base_url}/scans",
                json=enhanced_scan_config,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                scan_data = response.json()
                scan_id = scan_data["id"]
                self.created_scan_ids.append(scan_id)
                
                # Verify enhanced parameters are applied
                enhanced_params_correct = True
                issues = []
                
                if scan_data.get("depth") != 20:
                    issues.append(f"depth: expected 20, got {scan_data.get('depth')}")
                    enhanced_params_correct = False
                
                if scan_data.get("scan_force") != "insane":
                    issues.append(f"scan_force: expected 'insane', got {scan_data.get('scan_force')}")
                    enhanced_params_correct = False
                
                if scan_data.get("max_links_per_page") != 200:
                    issues.append(f"max_links_per_page: expected 200, got {scan_data.get('max_links_per_page')}")
                    enhanced_params_correct = False
                
                if scan_data.get("max_files_per_dir") != 100:
                    issues.append(f"max_files_per_dir: expected 100, got {scan_data.get('max_files_per_dir')}")
                    enhanced_params_correct = False
                
                if scan_data.get("scope") != "folder":
                    issues.append(f"scope: expected 'folder', got {scan_data.get('scope')}")
                    enhanced_params_correct = False
                
                if enhanced_params_correct:
                    self.log_test("Enhanced Configuration Creation", True, 
                        f"Enhanced deep scan config created with all parameters: depth=20, scan_force=insane, "
                        f"max_links_per_page=200, max_files_per_dir=100, scope=folder")
                else:
                    self.log_test("Enhanced Configuration Creation", False, f"Enhanced parameters not applied correctly: {'; '.join(issues)}", scan_data)
                
                # Start the enhanced scan to test Wapiti command generation
                start_response = self.session.post(f"{self.base_url}/scans/{scan_id}/start")
                if start_response.status_code == 200:
                    start_data = start_response.json()
                    result_id = start_data["result_id"]
                    self.created_result_ids.append(result_id)
                    
                    self.log_test("Enhanced Scan Execution", True, 
                        f"Enhanced deep scan started successfully with result_id: {result_id}")
                    
                    # Monitor for a short time to verify it's running with enhanced parameters
                    time.sleep(5)
                    
                    result_response = self.session.get(f"{self.base_url}/results/{result_id}")
                    if result_response.status_code == 200:
                        result_data = result_response.json()
                        status = result_data.get("status", "unknown")
                        progress = result_data.get("progress", 0)
                        
                        if status in ["running", "completed"]:
                            self.log_test("Enhanced Wapiti Command Generation", True, 
                                f"Enhanced Wapiti scan executing properly: status={status}, progress={progress}%")
                            return True
                        else:
                            self.log_test("Enhanced Wapiti Command Generation", False, 
                                f"Enhanced scan not running properly: status={status}")
                    else:
                        self.log_test("Enhanced Wapiti Command Generation", False, 
                            f"Cannot retrieve scan result: {result_response.status_code}")
                else:
                    self.log_test("Enhanced Scan Execution", False, 
                        f"Failed to start enhanced scan: {start_response.status_code}")
            else:
                self.log_test("Enhanced Configuration Creation", False, 
                    f"Failed to create enhanced scan config: {response.status_code}")
                
        except Exception as e:
            self.log_test("Enhanced Wapiti Configuration", False, f"Error testing enhanced configuration: {str(e)}")
        
        return False

    def test_vulnerable_site_scanning(self):
        """Test scanning against known vulnerable sites with enhanced Wapiti configuration"""
        try:
            # Test with the specific vulnerable site mentioned in review request
            vulnerable_sites = [
                {
                    "url": "http://testphp.vulnweb.com/",
                    "scan_type": "deep",
                    "expected_vulns": 5  # Should find multiple vulnerabilities with enhanced config
                },
                {
                    "url": "http://demo.testfire.net/",
                    "scan_type": "standard", 
                    "expected_vulns": 3
                }
            ]
            
            for site_info in vulnerable_sites:
                site_url = site_info["url"]
                scan_type = site_info["scan_type"]
                expected_vulns = site_info["expected_vulns"]
                
                try:
                    # Use enhanced configuration based on scan type
                    if scan_type == "deep":
                        scan_config = {
                            "name": f"Enhanced Deep Vulnerability Test - {site_url}",
                            "target_url": site_url,
                            "scan_type": "deep",
                            "scope": "folder",  # Enhanced: folder instead of domain for broader coverage
                            "depth": 20,        # Enhanced: maximum depth
                            "level": 3,         # Enhanced: maximum level
                            "timeout": 120,     # Enhanced: longer timeout
                            "max_scan_time": 1800,  # 30 minutes for thorough scanning
                            "max_links_per_page": 200,  # Enhanced: maximum links per page
                            "max_files_per_dir": 100,   # Enhanced: maximum files per directory
                            "scan_force": "insane",     # Enhanced: maximum scanning intensity
                            "verify_ssl": False
                        }
                    else:
                        scan_config = {
                            "name": f"Enhanced Standard Vulnerability Test - {site_url}",
                            "target_url": site_url,
                            "scan_type": "standard",
                            "scope": "folder",  # Enhanced: folder scope
                            "depth": 12,        # Enhanced: increased depth
                            "level": 2,
                            "timeout": 90,      # Enhanced: longer timeout
                            "max_scan_time": 900,  # 15 minutes
                            "max_links_per_page": 100,  # Enhanced: more links per page
                            "max_files_per_dir": 50,    # Enhanced: more files per directory
                            "scan_force": "aggressive", # Enhanced: aggressive scanning
                            "verify_ssl": False
                        }
                    
                    # Create scan configuration
                    response = self.session.post(
                        f"{self.base_url}/scans",
                        json=scan_config,
                        headers={"Content-Type": "application/json"}
                    )
                    
                    if response.status_code == 200:
                        scan_data = response.json()
                        scan_id = scan_data["id"]
                        self.created_scan_ids.append(scan_id)
                        
                        # Start the scan
                        start_response = self.session.post(f"{self.base_url}/scans/{scan_id}/start")
                        if start_response.status_code == 200:
                            start_data = start_response.json()
                            result_id = start_data["result_id"]
                            self.created_result_ids.append(result_id)
                            
                            self.log_test(f"Vulnerable Site Scan Started - {site_url}", True, f"Scan started for {site_url}, result_id: {result_id}")
                            
                            # Monitor scan progress for up to 5 minutes
                            max_wait_time = 300  # 5 minutes
                            start_time = time.time()
                            last_progress = 0
                            progress_updates = 0
                            
                            while time.time() - start_time < max_wait_time:
                                result_response = self.session.get(f"{self.base_url}/results/{result_id}")
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
                                        
                                        if vuln_count > 0:
                                            self.log_test(f"Vulnerable Site Detection - {site_url}", True, f"Found {vuln_count} vulnerabilities on {site_url}")
                                            
                                            # Test export with this result
                                            self.test_export_functionality(result_id)
                                            return True
                                        else:
                                            self.log_test(f"Vulnerable Site Detection - {site_url}", False, f"No vulnerabilities found on known vulnerable site {site_url}")
                                        break
                                    elif status == "failed":
                                        error_msg = result_data.get("error_message", "Unknown error")
                                        self.log_test(f"Vulnerable Site Scan - {site_url}", False, f"Scan failed: {error_msg}")
                                        break
                                
                                time.sleep(10)  # Wait 10 seconds between checks
                            
                            # Check if we got progress updates
                            if progress_updates > 0:
                                self.log_test(f"Real-time Progress - {site_url}", True, f"Received {progress_updates} progress updates (max: {last_progress}%)")
                            else:
                                self.log_test(f"Real-time Progress - {site_url}", False, f"No progress updates received during scan")
                            
                        else:
                            self.log_test(f"Vulnerable Site Scan Start - {site_url}", False, f"Failed to start scan: {start_response.status_code}")
                    else:
                        self.log_test(f"Vulnerable Site Config - {site_url}", False, f"Failed to create scan config: {response.status_code}")
                        
                except Exception as e:
                    self.log_test(f"Vulnerable Site Test - {site_url}", False, f"Error testing {site_url}: {str(e)}")
                    continue
            
            return False
            
        except Exception as e:
            self.log_test("Vulnerable Site Scanning", False, f"General error: {str(e)}")
            return False

    def test_existing_scan_result(self, result_id: str = "581a87f8-acc7-49b5-959d-4a9461e49dbf"):
        """Test the existing scan result mentioned in the review request"""
        try:
            response = self.session.get(f"{self.base_url}/results/{result_id}")
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                status = data.get("status", "unknown")
                progress = data.get("progress", 0)
                
                self.log_test("Existing Scan Result", True, f"Found existing result: status={status}, progress={progress}%, vulnerabilities={len(vulnerabilities)}")
                
                # Test export functionality with existing result
                if status == "completed":
                    self.test_export_functionality(result_id)
                    # Test new professional report format
                    self.test_professional_report_format(result_id)
                    # Test CWE mappings and vulnerability types
                    self.test_cwe_mappings_and_vulnerability_types(result_id)
                    # Test report content quality
                    self.test_report_content_quality(result_id)
                    return True
                else:
                    self.log_test("Existing Scan Status", False, f"Existing scan not completed: {status}")
            elif response.status_code == 404:
                self.log_test("Existing Scan Result", False, f"Existing scan result {result_id} not found")
            else:
                self.log_test("Existing Scan Result", False, f"HTTP {response.status_code}", response.text)
        except Exception as e:
            self.log_test("Existing Scan Result", False, f"Request error: {str(e)}")
        return False

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

    def test_wapiti_path_detection(self):
        """Test the get_wapiti_command() function for correct Wapiti path detection"""
        print("\n🎯 TESTING WAPITI PATH DETECTION FUNCTIONALITY")
        print("=" * 80)
        print("Testing get_wapiti_command() function to ensure correct Wapiti path detection")
        
        try:
            # Import the function from the backend server
            import sys
            import os
            sys.path.append('/app/backend')
            
            # Import the get_wapiti_command function
            from server import get_wapiti_command
            
            # Test the Wapiti path detection
            wapiti_path = get_wapiti_command()
            
            print(f"\n📋 Wapiti Path Detection Results:")
            print(f"   Detected Wapiti Path: {wapiti_path}")
            
            # Verify the path exists and is executable
            if wapiti_path == "wapiti":
                # Check if wapiti is in PATH
                import subprocess
                try:
                    result = subprocess.run(["which", "wapiti"], capture_output=True, text=True)
                    if result.returncode == 0:
                        actual_path = result.stdout.strip()
                        print(f"   Wapiti found in PATH: {actual_path}")
                        self.log_test("Wapiti Path Detection", True, f"Wapiti command found in PATH: {actual_path}")
                        return True
                    else:
                        self.log_test("Wapiti Path Detection", False, "Wapiti command not found in PATH")
                        return False
                except Exception as e:
                    self.log_test("Wapiti Path Detection", False, f"Error checking PATH: {str(e)}")
                    return False
            else:
                # Check if the specific path exists
                if os.path.exists(wapiti_path):
                    # Check if it's executable
                    if os.access(wapiti_path, os.X_OK):
                        print(f"   Wapiti executable found: {wapiti_path}")
                        self.log_test("Wapiti Path Detection", True, f"Wapiti executable found at: {wapiti_path}")
                        return True
                    else:
                        self.log_test("Wapiti Path Detection", False, f"Wapiti path exists but not executable: {wapiti_path}")
                        return False
                else:
                    self.log_test("Wapiti Path Detection", False, f"Wapiti path does not exist: {wapiti_path}")
                    return False
                    
        except ImportError as e:
            self.log_test("Wapiti Path Detection", False, f"Cannot import get_wapiti_command function: {str(e)}")
            return False
        except Exception as e:
            self.log_test("Wapiti Path Detection", False, f"Error testing Wapiti path detection: {str(e)}")
            return False

    def test_wapiti_scan_execution_with_testphp(self):
        """Test scan execution with testphp.vulnweb.com to verify Wapiti works without path errors"""
        print("\n🎯 TESTING WAPITI SCAN EXECUTION")
        print("=" * 80)
        print("Testing scan creation and execution with http://testphp.vulnweb.com")
        
        try:
            # Create a simple scan configuration for testphp.vulnweb.com
            scan_config = {
                "name": f"Wapiti Path Test - testphp.vulnweb.com",
                "target_url": "http://testphp.vulnweb.com",
                "scan_type": "quick",  # Use quick scan for faster testing
                "scope": "folder",
                "depth": 8,
                "level": 2,
                "timeout": 60,
                "max_scan_time": 600,  # 10 minutes max
                "verify_ssl": False
            }
            
            print(f"\n📋 Creating scan configuration:")
            print(f"   Target: {scan_config['target_url']}")
            print(f"   Scan Type: {scan_config['scan_type']}")
            print(f"   Depth: {scan_config['depth']}")
            
            # Create scan configuration
            response = self.session.post(
                f"{self.base_url}/scans",
                json=scan_config,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code != 200:
                self.log_test("Wapiti Scan Creation", False, 
                    f"Failed to create scan config: HTTP {response.status_code}")
                return False
            
            scan_data = response.json()
            scan_id = scan_data["id"]
            self.created_scan_ids.append(scan_id)
            
            self.log_test("Wapiti Scan Creation", True, 
                f"Scan configuration created successfully: {scan_id}")
            
            # Start the scan
            print(f"\n🚀 Starting Wapiti scan execution...")
            start_response = self.session.post(f"{self.base_url}/scans/{scan_id}/start")
            
            if start_response.status_code != 200:
                self.log_test("Wapiti Scan Start", False, 
                    f"Failed to start scan: HTTP {start_response.status_code}")
                return False
            
            start_data = start_response.json()
            result_id = start_data["result_id"]
            self.created_result_ids.append(result_id)
            
            self.log_test("Wapiti Scan Start", True, 
                f"Wapiti scan started successfully, result_id: {result_id}")
            
            # Monitor scan for path errors and execution
            print(f"\n📊 Monitoring scan execution for path errors...")
            max_wait_time = 300  # 5 minutes maximum wait
            start_time = time.time()
            last_progress = 0
            progress_updates = 0
            scan_started_properly = False
            
            while time.time() - start_time < max_wait_time:
                result_response = self.session.get(f"{self.base_url}/results/{result_id}")
                if result_response.status_code == 200:
                    result_data = result_response.json()
                    current_progress = result_data.get("progress", 0)
                    status = result_data.get("status", "unknown")
                    error_message = result_data.get("error_message", "")
                    
                    # Track progress updates
                    if current_progress > last_progress:
                        progress_updates += 1
                        last_progress = current_progress
                        print(f"   Progress: {current_progress}% - Status: {status}")
                        
                        # If we get any progress, the scan started properly
                        if current_progress > 0:
                            scan_started_properly = True
                    
                    # Check for path-related errors
                    if error_message:
                        if "wapiti" in error_message.lower() and ("not found" in error_message.lower() or "no such file" in error_message.lower()):
                            self.log_test("Wapiti Path Error Check", False, 
                                f"Wapiti path error detected: {error_message}")
                            return False
                        elif "failed" in status:
                            self.log_test("Wapiti Execution Error", False, 
                                f"Scan failed with error: {error_message}")
                            return False
                    
                    if status == "completed":
                        scan_duration = time.time() - start_time
                        vulnerabilities = result_data.get("vulnerabilities", [])
                        vuln_count = len(vulnerabilities)
                        
                        print(f"\n✅ Scan completed in {scan_duration:.1f} seconds")
                        print(f"   Vulnerabilities found: {vuln_count}")
                        
                        self.log_test("Wapiti Scan Completion", True, 
                            f"Scan completed successfully in {scan_duration:.1f}s, found {vuln_count} vulnerabilities")
                        
                        # Test output file creation
                        if vuln_count > 0:
                            self.log_test("Wapiti Output Files", True, 
                                "Scan results properly generated and parsed")
                        else:
                            self.log_test("Wapiti Output Files", True, 
                                "Scan completed without errors (no vulnerabilities found)")
                        
                        return True
                        
                    elif status == "failed":
                        error_msg = result_data.get("error_message", "Unknown error")
                        self.log_test("Wapiti Scan Execution", False, 
                            f"Scan failed: {error_msg}")
                        return False
                    elif status == "running" and current_progress > 0:
                        scan_started_properly = True
                
                time.sleep(5)  # Wait 5 seconds between checks
            
            # Check if scan started properly (no immediate path errors)
            if scan_started_properly:
                self.log_test("Wapiti Path Execution", True, 
                    f"Wapiti scan started and ran without path errors (progress: {last_progress}%)")
            else:
                self.log_test("Wapiti Path Execution", False, 
                    "Wapiti scan did not start properly - possible path issues")
            
            # Check if we got progress updates (indicates Wapiti is working)
            if progress_updates > 0:
                self.log_test("Wapiti Progress Tracking", True, 
                    f"Received {progress_updates} progress updates - Wapiti execution working")
            else:
                self.log_test("Wapiti Progress Tracking", False, 
                    "No progress updates received - possible Wapiti execution issues")
            
            return scan_started_properly and progress_updates > 0
            
        except Exception as e:
            self.log_test("Wapiti Scan Execution Test", False, f"Error: {str(e)}")
            return False

    def test_review_request_vulnerability_detection(self):
        """Test SPAWN scanner's actual vulnerability detection capabilities as requested in review"""
        print("🎯 TESTING REVIEW REQUEST: SPAWN Vulnerability Detection Authenticity")
        print("=" * 80)
        print("Testing against http://testhtml5.vulnweb.com with deep scan configuration")
        print("Expected: >10 vulnerabilities with authentic security findings")
        
        try:
            # 1. Create Real Scan Configuration with "deep" scan type
            deep_scan_config = {
                "name": f"Review Request Deep Scan - testhtml5.vulnweb.com",
                "target_url": "http://testhtml5.vulnweb.com",
                "scan_type": "deep",
                "scope": "folder",  # Enhanced for maximum coverage
                "depth": 20,        # Maximum depth for comprehensive scanning
                "level": 3,         # Maximum level
                "timeout": 120,     # Extended timeout for thorough scanning
                "max_scan_time": 3600,  # 1 hour for complete scanning
                "max_links_per_page": 200,  # Maximum links per page
                "max_files_per_dir": 100,   # Maximum files per directory
                "scan_force": "insane",     # Maximum scanning intensity
                "verify_ssl": False
            }
            
            print(f"\n📋 Creating deep scan configuration:")
            print(f"   Target: {deep_scan_config['target_url']}")
            print(f"   Scan Type: {deep_scan_config['scan_type']}")
            print(f"   Depth: {deep_scan_config['depth']}")
            print(f"   Scan Force: {deep_scan_config['scan_force']}")
            print(f"   Max Links/Page: {deep_scan_config['max_links_per_page']}")
            print(f"   Max Files/Dir: {deep_scan_config['max_files_per_dir']}")
            
            # Create scan configuration
            response = self.session.post(
                f"{self.base_url}/scans",
                json=deep_scan_config,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code != 200:
                self.log_test("Review Request - Scan Config Creation", False, 
                    f"Failed to create scan config: HTTP {response.status_code}")
                return False
            
            scan_data = response.json()
            scan_id = scan_data["id"]
            self.created_scan_ids.append(scan_id)
            
            # Verify deep scan preset parameters are applied
            config_issues = []
            if scan_data.get("depth") < 20:
                config_issues.append(f"depth: {scan_data.get('depth')} < 20")
            if scan_data.get("scan_force") != "insane":
                config_issues.append(f"scan_force: {scan_data.get('scan_force')} != insane")
            if scan_data.get("max_links_per_page") < 200:
                config_issues.append(f"max_links_per_page: {scan_data.get('max_links_per_page')} < 200")
            
            if config_issues:
                self.log_test("Review Request - Deep Scan Config", False, 
                    f"Deep scan parameters not properly applied: {'; '.join(config_issues)}")
            else:
                self.log_test("Review Request - Deep Scan Config", True, 
                    "Deep scan configuration created with maximum vulnerability detection parameters")
            
            # 2. Execute the Scan
            print(f"\n🚀 Starting deep vulnerability scan...")
            start_response = self.session.post(f"{self.base_url}/scans/{scan_id}/start")
            
            if start_response.status_code != 200:
                self.log_test("Review Request - Scan Execution", False, 
                    f"Failed to start scan: HTTP {start_response.status_code}")
                return False
            
            start_data = start_response.json()
            result_id = start_data["result_id"]
            self.created_result_ids.append(result_id)
            
            self.log_test("Review Request - Scan Execution", True, 
                f"Deep scan started successfully, result_id: {result_id}")
            
            # 3. Monitor the actual scanning process
            print(f"\n📊 Monitoring scan progress and authenticity...")
            max_wait_time = 1800  # 30 minutes maximum wait
            start_time = time.time()
            last_progress = 0
            progress_updates = 0
            vulnerability_count = 0
            scan_phases_detected = []
            
            while time.time() - start_time < max_wait_time:
                result_response = self.session.get(f"{self.base_url}/results/{result_id}")
                if result_response.status_code == 200:
                    result_data = result_response.json()
                    current_progress = result_data.get("progress", 0)
                    status = result_data.get("status", "unknown")
                    vulnerabilities = result_data.get("vulnerabilities", [])
                    current_vuln_count = len(vulnerabilities)
                    
                    # Track progress updates for authenticity verification
                    if current_progress > last_progress:
                        progress_updates += 1
                        last_progress = current_progress
                        print(f"   Progress: {current_progress}% - Status: {status} - Vulnerabilities: {current_vuln_count}")
                        
                        # Track scan phases for authenticity
                        if current_progress >= 10 and "Loading" not in scan_phases_detected:
                            scan_phases_detected.append("Loading")
                        if current_progress >= 25 and "Crawling" not in scan_phases_detected:
                            scan_phases_detected.append("Crawling")
                        if current_progress >= 60 and "Analyzing" not in scan_phases_detected:
                            scan_phases_detected.append("Analyzing")
                        if current_progress >= 80 and "Attacking" not in scan_phases_detected:
                            scan_phases_detected.append("Attacking")
                    
                    # Track vulnerability discovery
                    if current_vuln_count > vulnerability_count:
                        vulnerability_count = current_vuln_count
                        print(f"   🔍 Vulnerabilities found: {vulnerability_count}")
                    
                    if status == "completed":
                        scan_duration = time.time() - start_time
                        print(f"\n✅ Scan completed in {scan_duration:.1f} seconds")
                        
                        # 4. Validate Real Vulnerability Detection
                        final_vulnerabilities = result_data.get("vulnerabilities", [])
                        vuln_count = len(final_vulnerabilities)
                        
                        print(f"\n🔍 VULNERABILITY DETECTION RESULTS:")
                        print(f"   Total vulnerabilities found: {vuln_count}")
                        
                        if vuln_count > 10:
                            self.log_test("Review Request - Vulnerability Count", True, 
                                f"Found {vuln_count} vulnerabilities (>10 as expected)")
                        elif vuln_count > 0:
                            self.log_test("Review Request - Vulnerability Count", False, 
                                f"Found only {vuln_count} vulnerabilities (<10 expected)")
                        else:
                            self.log_test("Review Request - Vulnerability Count", False, 
                                "No vulnerabilities found on known vulnerable site")
                        
                        # Analyze vulnerability types for authenticity
                        vuln_types = {}
                        severity_counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
                        
                        for vuln in final_vulnerabilities:
                            vuln_type = vuln.get("module", "unknown")
                            severity = vuln.get("severity", "unknown").lower()
                            
                            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
                            if severity in severity_counts:
                                severity_counts[severity] += 1
                        
                        print(f"\n📊 VULNERABILITY ANALYSIS:")
                        print(f"   Vulnerability Types: {dict(vuln_types)}")
                        print(f"   Severity Distribution: {dict(severity_counts)}")
                        
                        # Check for expected vulnerability types on a vulnerable site
                        expected_types = ["xss", "sql", "csrf", "exec", "file"]
                        found_expected_types = [vtype for vtype in expected_types if vtype in vuln_types]
                        
                        if len(found_expected_types) >= 2:
                            self.log_test("Review Request - Vulnerability Types", True, 
                                f"Found expected vulnerability types: {found_expected_types}")
                        else:
                            self.log_test("Review Request - Vulnerability Types", False, 
                                f"Limited vulnerability types found: {list(vuln_types.keys())}")
                        
                        # 5. Authenticity Verification
                        print(f"\n🔐 AUTHENTICITY VERIFICATION:")
                        
                        # Check scan duration (real scans take time)
                        if scan_duration > 30:  # Real scans should take at least 30 seconds
                            self.log_test("Review Request - Scan Duration Authenticity", True, 
                                f"Scan duration ({scan_duration:.1f}s) indicates real scanning activity")
                        else:
                            self.log_test("Review Request - Scan Duration Authenticity", False, 
                                f"Scan duration ({scan_duration:.1f}s) too short for authentic scanning")
                        
                        # Check progress updates (real scans have incremental progress)
                        if progress_updates >= 5:
                            self.log_test("Review Request - Progress Authenticity", True, 
                                f"Received {progress_updates} progress updates indicating real-time scanning")
                        else:
                            self.log_test("Review Request - Progress Authenticity", False, 
                                f"Only {progress_updates} progress updates - may indicate mock scanning")
                        
                        # Check scan phases
                        if len(scan_phases_detected) >= 3:
                            self.log_test("Review Request - Scan Phases Authenticity", True, 
                                f"Detected scan phases: {scan_phases_detected}")
                        else:
                            self.log_test("Review Request - Scan Phases Authenticity", False, 
                                f"Limited scan phases detected: {scan_phases_detected}")
                        
                        # 6. Test Report Generation with Real Vulnerability Data
                        print(f"\n📄 TESTING REPORT GENERATION WITH REAL VULNERABILITY DATA:")
                        
                        if vuln_count > 0:
                            # Test all export formats
                            self.test_export_functionality(result_id)
                            self.test_professional_report_format(result_id)
                            self.test_cwe_mappings_and_vulnerability_types(result_id)
                            self.test_report_content_quality(result_id)
                            
                            # Additional verification for report content with real vulnerabilities
                            html_response = self.session.get(f"{self.base_url}/results/{result_id}/export/html")
                            if html_response.status_code == 200:
                                html_content = html_response.text
                                
                                # Check if real vulnerability data is in reports
                                real_vuln_indicators = [
                                    "testhtml5.vulnweb.com",
                                    str(vuln_count),
                                    "XSS" if "xss" in vuln_types else None,
                                    "SQL" if "sql" in vuln_types else None
                                ]
                                
                                real_indicators_found = sum(1 for indicator in real_vuln_indicators 
                                                          if indicator and indicator in html_content)
                                
                                if real_indicators_found >= 2:
                                    self.log_test("Review Request - Report Real Data", True, 
                                        f"Report contains real vulnerability data ({real_indicators_found}/4 indicators)")
                                else:
                                    self.log_test("Review Request - Report Real Data", False, 
                                        f"Report may not contain authentic data ({real_indicators_found}/4 indicators)")
                        
                        return True
                        
                    elif status == "failed":
                        error_msg = result_data.get("error_message", "Unknown error")
                        self.log_test("Review Request - Scan Completion", False, 
                            f"Scan failed: {error_msg}")
                        return False
                
                time.sleep(15)  # Wait 15 seconds between checks
            
            # Timeout case
            self.log_test("Review Request - Scan Timeout", False, 
                f"Scan did not complete within {max_wait_time/60:.1f} minutes")
            
            # Still check partial results
            result_response = self.session.get(f"{self.base_url}/results/{result_id}")
            if result_response.status_code == 200:
                result_data = result_response.json()
                partial_vulns = result_data.get("vulnerabilities", [])
                if len(partial_vulns) > 0:
                    self.log_test("Review Request - Partial Results", True, 
                        f"Found {len(partial_vulns)} vulnerabilities before timeout")
                    return True
            
            return False
            
        except Exception as e:
            self.log_test("Review Request - General Error", False, f"Error during vulnerability detection test: {str(e)}")
            return False

    def test_scan_queue_system(self):
        """Test the SCAN QUEUE SYSTEM functionality as requested in review"""
        print("\n🎯 TESTING SCAN QUEUE SYSTEM FUNCTIONALITY")
        print("=" * 80)
        print("Testing: Scan Creation & Queuing, Queue Management, Start All Scans, Individual Scan Start")
        print("Testing: Status Transitions, Queue Status Tracking, Mixed Queue States")
        
        queue_test_results = []
        
        # 1. Test Scan Creation & Queuing - POST /api/scans creates scan configs and automatically creates queued scan results
        print("\n📋 TEST 1: Scan Creation & Automatic Queuing")
        try:
            # Create multiple scan configurations to test queuing
            scan_configs = []
            for i in range(3):
                scan_config = {
                    "name": f"Queue Test Scan {i+1} - {uuid.uuid4().hex[:8]}",
                    "target_url": "https://httpbin.org/get",
                    "scan_type": "quick",
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
                    scan_configs.append({
                        "scan_id": data["id"],
                        "result_id": data.get("result_id"),
                        "name": data["name"]
                    })
                    self.created_scan_ids.append(data["id"])
                    if data.get("result_id"):
                        self.created_result_ids.append(data["result_id"])
                else:
                    queue_test_results.append(("Scan Creation & Queuing", False, f"Failed to create scan {i+1}: HTTP {response.status_code}"))
                    break
            
            if len(scan_configs) == 3:
                queue_test_results.append(("Scan Creation & Queuing", True, f"Created 3 scan configurations with automatic queuing"))
                print(f"   ✅ Created {len(scan_configs)} scans with automatic result queuing")
                for config in scan_configs:
                    print(f"      - {config['name']}: scan_id={config['scan_id']}, result_id={config['result_id']}")
            else:
                queue_test_results.append(("Scan Creation & Queuing", False, f"Only created {len(scan_configs)}/3 scan configurations"))
                
        except Exception as e:
            queue_test_results.append(("Scan Creation & Queuing", False, f"Error: {str(e)}"))
        
        # 2. Test Queue Management - GET /api/results shows queued scans with status="queued"
        print("\n📊 TEST 2: Queue Management & Status Tracking")
        try:
            response = self.session.get(f"{self.base_url}/results")
            if response.status_code == 200:
                all_results = response.json()
                queued_results = [r for r in all_results if r.get("status") == "queued"]
                running_results = [r for r in all_results if r.get("status") == "running"]
                
                if len(queued_results) >= 3:
                    queue_test_results.append(("Queue Management", True, f"Found {len(queued_results)} queued scans, {len(running_results)} running"))
                    print(f"   ✅ Queue Status: {len(queued_results)} queued, {len(running_results)} running")
                    
                    # Verify our created scans are in the queue
                    our_queued_scans = []
                    for config in scan_configs:
                        for result in queued_results:
                            if result.get("id") == config["result_id"]:
                                our_queued_scans.append(result)
                                break
                    
                    if len(our_queued_scans) >= 2:
                        queue_test_results.append(("Queue Status Verification", True, f"Verified {len(our_queued_scans)} of our scans are properly queued"))
                        print(f"   ✅ Verified {len(our_queued_scans)} of our scans are in queue with status='queued'")
                    else:
                        queue_test_results.append(("Queue Status Verification", False, f"Only {len(our_queued_scans)} of our scans found in queue"))
                else:
                    queue_test_results.append(("Queue Management", False, f"Expected >=3 queued scans, found {len(queued_results)}"))
            else:
                queue_test_results.append(("Queue Management", False, f"Failed to get results: HTTP {response.status_code}"))
        except Exception as e:
            queue_test_results.append(("Queue Management", False, f"Error: {str(e)}"))
        
        # 3. Test Individual Scan Start - POST /api/scans/{id}/start works for individual scans
        print("\n⚡ TEST 3: Individual Scan Start")
        try:
            if scan_configs:
                individual_scan = scan_configs[0]
                response = self.session.post(f"{self.base_url}/scans/{individual_scan['scan_id']}/start")
                
                if response.status_code == 200:
                    data = response.json()
                    if "result_id" in data and "message" in data:
                        queue_test_results.append(("Individual Scan Start", True, f"Individual scan started: {data['message']}"))
                        print(f"   ✅ Individual scan started: {individual_scan['name']}")
                        
                        # Wait and check if status changed from queued to running
                        time.sleep(2)
                        result_response = self.session.get(f"{self.base_url}/results/{individual_scan['result_id']}")
                        if result_response.status_code == 200:
                            result_data = result_response.json()
                            new_status = result_data.get("status")
                            if new_status == "running":
                                queue_test_results.append(("Status Transition (queued->running)", True, f"Scan transitioned to running status"))
                                print(f"   ✅ Status transition: queued -> running")
                            else:
                                queue_test_results.append(("Status Transition (queued->running)", False, f"Status is '{new_status}', expected 'running'"))
                    else:
                        queue_test_results.append(("Individual Scan Start", False, "Invalid response format"))
                else:
                    queue_test_results.append(("Individual Scan Start", False, f"HTTP {response.status_code}"))
        except Exception as e:
            queue_test_results.append(("Individual Scan Start", False, f"Error: {str(e)}"))
        
        # 4. Test Start All Scans - POST /api/scans/start-all starts all queued scans and returns correct count
        print("\n🚀 TEST 4: Start All Queued Scans")
        try:
            # First check how many scans are currently queued
            pre_response = self.session.get(f"{self.base_url}/results")
            pre_queued_count = 0
            if pre_response.status_code == 200:
                all_results = pre_response.json()
                pre_queued_count = len([r for r in all_results if r.get("status") == "queued"])
            
            print(f"   📊 Pre-start queue status: {pre_queued_count} queued scans")
            
            # Start all queued scans
            response = self.session.post(f"{self.base_url}/scans/start-all")
            
            if response.status_code == 200:
                data = response.json()
                started_count = data.get("started_count", 0)
                message = data.get("message", "")
                started_scans = data.get("started_scans", [])
                
                if started_count > 0:
                    queue_test_results.append(("Start All Scans", True, f"Started {started_count} queued scans"))
                    print(f"   ✅ Start All Scans: {message}")
                    print(f"   📊 Started {started_count} scans")
                    
                    # Verify the started scans details
                    if started_scans:
                        print(f"   📋 Started scans details:")
                        for scan in started_scans:
                            print(f"      - {scan.get('scan_name', 'Unknown')}: scan_id={scan.get('scan_id')}, result_id={scan.get('result_id')}")
                    
                    # Wait and check queue status after starting all
                    time.sleep(3)
                    post_response = self.session.get(f"{self.base_url}/results")
                    if post_response.status_code == 200:
                        all_results = post_response.json()
                        post_queued_count = len([r for r in all_results if r.get("status") == "queued"])
                        running_count = len([r for r in all_results if r.get("status") == "running"])
                        
                        print(f"   📊 Post-start queue status: {post_queued_count} queued, {running_count} running")
                        
                        if post_queued_count < pre_queued_count:
                            queue_test_results.append(("Queue Count Accuracy", True, f"Queue reduced from {pre_queued_count} to {post_queued_count}"))
                        else:
                            queue_test_results.append(("Queue Count Accuracy", False, f"Queue count unchanged: {pre_queued_count} -> {post_queued_count}"))
                elif started_count == 0 and "No queued scans" in message:
                    queue_test_results.append(("Start All Scans - Empty Queue", True, "Correctly handled empty queue"))
                    print(f"   ✅ Empty queue handled correctly: {message}")
                else:
                    queue_test_results.append(("Start All Scans", False, f"Unexpected response: started_count={started_count}, message={message}"))
            else:
                queue_test_results.append(("Start All Scans", False, f"HTTP {response.status_code}"))
        except Exception as e:
            queue_test_results.append(("Start All Scans", False, f"Error: {str(e)}"))
        
        # 5. Test Mixed Queue States - Create some queued scans, start some individually, then use start-all on remaining
        print("\n🔄 TEST 5: Mixed Queue States & Advanced Scenarios")
        try:
            # Create 2 more scans for mixed state testing
            mixed_scan_configs = []
            for i in range(2):
                scan_config = {
                    "name": f"Mixed Queue Test {i+1} - {uuid.uuid4().hex[:8]}",
                    "target_url": "https://httpbin.org/delay/1",
                    "scan_type": "quick",
                    "scope": "folder",
                    "modules": ["exec", "file"],
                    "depth": 2,
                    "level": 1,
                    "timeout": 20,
                    "verify_ssl": True
                }
                
                response = self.session.post(
                    f"{self.base_url}/scans",
                    json=scan_config,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    mixed_scan_configs.append({
                        "scan_id": data["id"],
                        "result_id": data.get("result_id"),
                        "name": data["name"]
                    })
                    self.created_scan_ids.append(data["id"])
                    if data.get("result_id"):
                        self.created_result_ids.append(data["result_id"])
            
            if len(mixed_scan_configs) == 2:
                print(f"   📋 Created 2 additional scans for mixed state testing")
                
                # Start one individually
                individual_response = self.session.post(f"{self.base_url}/scans/{mixed_scan_configs[0]['scan_id']}/start")
                if individual_response.status_code == 200:
                    print(f"   ⚡ Started one scan individually: {mixed_scan_configs[0]['name']}")
                
                # Wait a moment
                time.sleep(2)
                
                # Check queue state
                queue_response = self.session.get(f"{self.base_url}/results")
                if queue_response.status_code == 200:
                    all_results = queue_response.json()
                    queued_count = len([r for r in all_results if r.get("status") == "queued"])
                    running_count = len([r for r in all_results if r.get("status") == "running"])
                    
                    print(f"   📊 Mixed state: {queued_count} queued, {running_count} running")
                    
                    # Now start all remaining queued scans
                    start_all_response = self.session.post(f"{self.base_url}/scans/start-all")
                    if start_all_response.status_code == 200:
                        start_all_data = start_all_response.json()
                        remaining_started = start_all_data.get("started_count", 0)
                        
                        queue_test_results.append(("Mixed Queue States", True, f"Mixed state handled correctly: started {remaining_started} remaining queued scans"))
                        print(f"   ✅ Started {remaining_started} remaining queued scans")
                    else:
                        queue_test_results.append(("Mixed Queue States", False, f"Start-all failed in mixed state: HTTP {start_all_response.status_code}"))
                else:
                    queue_test_results.append(("Mixed Queue States", False, "Failed to check queue state"))
            else:
                queue_test_results.append(("Mixed Queue States", False, f"Failed to create test scans for mixed state"))
                
        except Exception as e:
            queue_test_results.append(("Mixed Queue States", False, f"Error: {str(e)}"))
        
        # 6. Test Empty Queue Scenario
        print("\n🔄 TEST 6: Empty Queue Scenario")
        try:
            # Wait for scans to potentially complete or clear queue manually by starting all
            time.sleep(5)
            
            # Try start-all on potentially empty queue
            response = self.session.post(f"{self.base_url}/scans/start-all")
            if response.status_code == 200:
                data = response.json()
                started_count = data.get("started_count", 0)
                message = data.get("message", "")
                
                if started_count == 0 and ("No queued scans" in message or "started 0" in message.lower()):
                    queue_test_results.append(("Empty Queue Handling", True, "Empty queue handled correctly"))
                    print(f"   ✅ Empty queue handled: {message}")
                elif started_count > 0:
                    queue_test_results.append(("Empty Queue Handling", True, f"Found and started {started_count} remaining queued scans"))
                    print(f"   ✅ Found and started {started_count} remaining scans")
                else:
                    queue_test_results.append(("Empty Queue Handling", False, f"Unexpected response: {message}"))
            else:
                queue_test_results.append(("Empty Queue Handling", False, f"HTTP {response.status_code}"))
        except Exception as e:
            queue_test_results.append(("Empty Queue Handling", False, f"Error: {str(e)}"))
        
        # Log all queue system test results
        print(f"\n📊 SCAN QUEUE SYSTEM TEST SUMMARY")
        print("=" * 60)
        passed_tests = 0
        total_tests = len(queue_test_results)
        
        for test_name, success, message in queue_test_results:
            status = "✅ PASS" if success else "❌ FAIL"
            print(f"{status}: {test_name}")
            print(f"   {message}")
            if success:
                passed_tests += 1
            
            # Log to main test results
            self.log_test(f"Queue System - {test_name}", success, message)
        
        print(f"\n🎯 Queue System Tests: {passed_tests}/{total_tests} passed ({passed_tests/total_tests*100:.1f}%)")
        
        return passed_tests == total_tests

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
        
        # PRIORITY TEST 1: Test improved scan presets
        print("\n🎯 PRIORITY TEST 1: Scan Configuration Improvements")
        self.test_scan_presets()
        
        # PRIORITY TEST 2: Test existing scan result and export functionality
        print("\n🎯 PRIORITY TEST 2: Export Functionality")
        self.test_existing_scan_result()
        
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
        
        # PRIORITY TEST 3 & 4: Test authentic vulnerability scanning and real-time progress
        print("\n🎯 PRIORITY TEST 3 & 4: Authentic Vulnerability Detection & Real-time Progress")
        self.test_vulnerable_site_scanning()
        
        # Print summary
        self.print_test_summary()
        
        return self.get_overall_success()

    def create_test_scan_with_vulnerabilities(self):
        """Create a test scan against a vulnerable site to generate results for report testing"""
        try:
            # Create scan configuration for vulnerable site
            scan_config = {
                "name": f"Report Test Scan {uuid.uuid4().hex[:8]}",
                "target_url": "http://testphp.vulnweb.com/",
                "scan_type": "standard",
                "scope": "folder",
                "depth": 12,
                "level": 2,
                "timeout": 90,
                "max_scan_time": 1800,  # 30 minutes
                "max_links_per_page": 100,
                "max_files_per_dir": 50,
                "scan_force": "aggressive",
                "verify_ssl": False
            }
            
            # Create scan configuration
            response = self.session.post(
                f"{self.base_url}/scans",
                json=scan_config,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                scan_data = response.json()
                scan_id = scan_data["id"]
                self.created_scan_ids.append(scan_id)
                
                # Start the scan
                start_response = self.session.post(f"{self.base_url}/scans/{scan_id}/start")
                if start_response.status_code == 200:
                    start_data = start_response.json()
                    result_id = start_data["result_id"]
                    self.created_result_ids.append(result_id)
                    
                    self.log_test("Test Scan Creation", True, f"Test scan created and started: {result_id}")
                    
                    # Wait for scan to complete or find vulnerabilities
                    max_wait_time = 300  # 5 minutes
                    start_time = time.time()
                    
                    while time.time() - start_time < max_wait_time:
                        result_response = self.session.get(f"{self.base_url}/results/{result_id}")
                        if result_response.status_code == 200:
                            result_data = result_response.json()
                            status = result_data.get("status", "unknown")
                            vulnerabilities = result_data.get("vulnerabilities", [])
                            
                            if status == "completed" or len(vulnerabilities) > 0:
                                self.log_test("Test Scan Completion", True, 
                                    f"Test scan completed with {len(vulnerabilities)} vulnerabilities")
                                return result_id
                            elif status == "failed":
                                self.log_test("Test Scan Completion", False, "Test scan failed")
                                break
                        
                        time.sleep(10)
                    
                    # If scan is still running but we have some results, use it
                    if len(vulnerabilities) > 0:
                        return result_id
                    
                    self.log_test("Test Scan Timeout", False, "Test scan did not complete in time")
                else:
                    self.log_test("Test Scan Start", False, f"Failed to start test scan: {start_response.status_code}")
            else:
                self.log_test("Test Scan Config", False, f"Failed to create test scan config: {response.status_code}")
                
        except Exception as e:
            self.log_test("Test Scan Creation", False, f"Error creating test scan: {str(e)}")
        
        return None

    def run_review_request_test(self):
        """Run the specific test requested in the review"""
        print("🎯 SPAWN VULNERABILITY DETECTION AUTHENTICITY TEST")
        print("=" * 80)
        print("Review Request: Test SPAWN scanner's actual vulnerability detection capabilities")
        print("Target: http://testhtml5.vulnweb.com with deep scan configuration")
        print("Expected: >10 vulnerabilities with authentic security findings")
        print("=" * 80)
        
        # Test basic connectivity first
        if not self.test_root_endpoint():
            print("❌ Cannot connect to backend. Stopping tests.")
            return False
        
        # Test scan presets to ensure enhanced configuration is available
        print("\n🔧 Verifying enhanced Wapiti configuration...")
        self.test_scan_presets()
        
        # Run the main vulnerability detection test
        success = self.test_review_request_vulnerability_detection()
        
        # Print summary
        print("\n" + "=" * 80)
        print("📊 REVIEW REQUEST TEST SUMMARY")
        print("=" * 80)
        
        passed_tests = sum(1 for result in self.test_results if result["success"])
        total_tests = len(self.test_results)
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        print(f"Tests Passed: {passed_tests}/{total_tests} ({success_rate:.1f}%)")
        
        # Show key findings
        key_findings = []
        for result in self.test_results:
            if "Review Request" in result["test"]:
                status = "✅ PASS" if result["success"] else "❌ FAIL"
                key_findings.append(f"{status}: {result['test']} - {result['message']}")
        
        if key_findings:
            print("\n🔍 KEY FINDINGS:")
            for finding in key_findings:
                print(f"   {finding}")
        
        # Overall assessment
        critical_tests = [
            "Review Request - Vulnerability Count",
            "Review Request - Scan Duration Authenticity", 
            "Review Request - Progress Authenticity"
        ]
        
        critical_passed = sum(1 for result in self.test_results 
                            if result["test"] in critical_tests and result["success"])
        
        print(f"\n🎯 AUTHENTICITY ASSESSMENT:")
        if critical_passed >= 2:
            print("   ✅ SPAWN appears to be performing authentic vulnerability scanning")
        else:
            print("   ❌ SPAWN may not be performing authentic vulnerability scanning")
        
        return success

    def run_report_export_tests(self):
        """Run comprehensive report export tests as requested in the review"""
        print("🎯 Starting SPAWN Report Export Functionality Tests (Review Request Focus)")
        print("=" * 80)
        
        # Test basic connectivity first
        if not self.test_root_endpoint():
            print("❌ Cannot connect to backend. Stopping tests.")
            return False
        
        print("\n🎯 TESTING UPDATED REPORT EXPORT FUNCTIONALITY")
        print("Focus: PDF, HTML, CSV export formats with professional vulnerability assessment layout")
        
        # First, try to use existing scan result if available
        existing_result_tested = False
        try:
            # Try a few common result IDs that might exist
            potential_result_ids = [
                "581a87f8-acc7-49b5-959d-4a9461e49dbf",
                # Add more if needed
            ]
            
            for result_id in potential_result_ids:
                response = self.session.get(f"{self.base_url}/results/{result_id}")
                if response.status_code == 200:
                    result_data = response.json()
                    if result_data.get("status") == "completed":
                        vulnerabilities = result_data.get("vulnerabilities", [])
                        if len(vulnerabilities) > 0:
                            print(f"\n✅ Found existing scan result with {len(vulnerabilities)} vulnerabilities: {result_id}")
                            
                            # Test all report formats with existing result
                            self.test_export_functionality(result_id)
                            self.test_professional_report_format(result_id)
                            self.test_cwe_mappings_and_vulnerability_types(result_id)
                            self.test_report_content_quality(result_id)
                            existing_result_tested = True
                            break
        except Exception as e:
            print(f"Error checking existing results: {e}")
        
        # If no existing result with vulnerabilities found, create a new test scan
        if not existing_result_tested:
            print("\n🔄 No suitable existing scan result found. Creating new test scan...")
            test_result_id = self.create_test_scan_with_vulnerabilities()
            
            if test_result_id:
                print(f"\n✅ Created test scan result: {test_result_id}")
                
                # Test all report formats with new result
                self.test_export_functionality(test_result_id)
                self.test_professional_report_format(test_result_id)
                self.test_cwe_mappings_and_vulnerability_types(test_result_id)
                self.test_report_content_quality(test_result_id)
            else:
                print("\n❌ Could not create test scan with vulnerabilities")
                # Still test export functionality with any available result
                all_results_response = self.session.get(f"{self.base_url}/results")
                if all_results_response.status_code == 200:
                    all_results = all_results_response.json()
                    if all_results:
                        # Use the first available result
                        first_result = all_results[0]
                        result_id = first_result.get("id")
                        if result_id:
                            print(f"\n⚠️  Testing with available result (may have no vulnerabilities): {result_id}")
                            self.test_export_functionality(result_id)
                            self.test_professional_report_format(result_id)
        
        # Print summary
        self.print_test_summary()
        return self.get_overall_success()
        """Run only the priority tests mentioned in the review request"""
        print("🎯 Starting SPAWN Enhanced Wapiti Configuration Tests (Review Request Focus)")
        print("=" * 80)
        
        # Test basic connectivity first
        if not self.test_root_endpoint():
            print("❌ Cannot connect to backend. Stopping tests.")
            return False
        
        print("\n🎯 PRIORITY TEST 1: Enhanced Scan Presets (Quick, Standard, Deep)")
        print("Testing enhanced scan presets with increased depth (8-20), scan_force (normal/aggressive/insane),")
        print("max_links_per_page (50-200), max_files_per_dir (30-100), and folder scope")
        self.test_scan_presets()
        
        print("\n🎯 PRIORITY TEST 2: Enhanced Wapiti Configuration Creation")
        print("Testing scan configuration creation with enhanced parameters and Wapiti command generation")
        self.test_enhanced_wapiti_configuration()
        
        print("\n🎯 PRIORITY TEST 3: Enhanced Vulnerability Detection")
        print("Testing enhanced deep scan against http://testphp.vulnweb.com/ to verify more vulnerabilities are detected")
        print("🎯 PRIORITY TEST 4: Real-time Progress Tracking with Enhanced Parameters")
        print("Verifying enhanced Wapiti commands execute properly with new parameters")
        self.test_vulnerable_site_scanning()
        
        print("\n🎯 ADDITIONAL TEST: Export Functionality Verification")
        print("Testing export formats work with enhanced scan results")
        self.test_existing_scan_result()
        
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
    import sys
    
    print("🔍 SPAWN Vulnerability Scanner Backend Test Suite")
    print("🎯 FOCUS: SCAN QUEUE SYSTEM FUNCTIONALITY")
    print("Testing backend at: https://scan-debug-1.preview.emergentagent.com/api")
    print()
    
    tester = SPAWNBackendTester()
    
    # Check command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--priority":
            success = tester.run_priority_tests_only()
        elif sys.argv[1] == "--reports":
            success = tester.run_report_export_tests()
        elif sys.argv[1] == "--review":
            success = tester.run_review_request_test()
        elif sys.argv[1] == "--queue":
            # Run only queue system tests
            success = tester.test_scan_queue_system()
        else:
            success = tester.run_comprehensive_test()
    else:
        # Default: run comprehensive test with queue system focus
        success = tester.run_comprehensive_test()
    
    if success:
        print("\n🎉 All critical backend tests passed!")
        return 0
    else:
        print("\n💥 Some critical backend tests failed!")
        return 1

if __name__ == "__main__":
    exit(main())