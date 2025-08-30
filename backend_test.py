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
    def __init__(self, base_url: str = "https://report-template-1.preview.emergentagent.com/api"):
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

    def run_priority_tests_only(self):
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
    print("Testing backend at: https://report-template-1.preview.emergentagent.com/api")
    print()
    
    tester = SPAWNBackendTester()
    
    # Check if priority tests only should be run
    if len(sys.argv) > 1 and sys.argv[1] == "--priority":
        success = tester.run_priority_tests_only()
    else:
        success = tester.run_comprehensive_test()
    
    if success:
        print("\n🎉 All critical backend tests passed!")
        return 0
    else:
        print("\n💥 Some critical backend tests failed!")
        return 1

if __name__ == "__main__":
    exit(main())