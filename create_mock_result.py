#!/usr/bin/env python3
"""
Create a mock scan result with vulnerabilities for testing report formats
"""

import requests
import json
import uuid
from datetime import datetime, timezone

def create_mock_result_with_vulnerabilities():
    """Create a mock scan result with sample vulnerabilities"""
    
    base_url = "https://report-template-1.preview.emergentagent.com/api"
    
    # First create a scan configuration
    scan_config = {
        "name": "Mock Vulnerability Test Scan",
        "target_url": "http://testphp.vulnweb.com/",
        "scan_type": "standard",
        "scope": "folder",
        "modules": ["xss", "sql", "csrf", "exec", "file"],
        "depth": 5,
        "level": 2,
        "timeout": 60,
        "verify_ssl": False
    }
    
    # Create scan configuration
    response = requests.post(f"{base_url}/scans", json=scan_config)
    if response.status_code != 200:
        print(f"Failed to create scan config: {response.status_code}")
        return None
    
    scan_data = response.json()
    scan_id = scan_data["id"]
    print(f"Created scan config: {scan_id}")
    
    # Start the scan to create a result
    start_response = requests.post(f"{base_url}/scans/{scan_id}/start")
    if start_response.status_code != 200:
        print(f"Failed to start scan: {start_response.status_code}")
        return None
    
    start_data = start_response.json()
    result_id = start_data["result_id"]
    print(f"Created scan result: {result_id}")
    
    # Now we need to manually update this result with mock vulnerabilities
    # Since we can't directly access the database, we'll use the existing result
    # and create a new scan that might find vulnerabilities
    
    return result_id

if __name__ == "__main__":
    result_id = create_mock_result_with_vulnerabilities()
    if result_id:
        print(f"Mock result created: {result_id}")
        
        # Test the export functionality
        base_url = "https://report-template-1.preview.emergentagent.com/api"
        
        # Wait a moment for the scan to potentially find something
        import time
        time.sleep(10)
        
        # Check the result
        result_response = requests.get(f"{base_url}/results/{result_id}")
        if result_response.status_code == 200:
            result_data = result_response.json()
            print(f"Result status: {result_data.get('status')}")
            print(f"Vulnerabilities: {len(result_data.get('vulnerabilities', []))}")
            
            # Test HTML export
            html_response = requests.get(f"{base_url}/results/{result_id}/export/html")
            if html_response.status_code == 200:
                print(f"HTML export successful: {len(html_response.text)} chars")
            else:
                print(f"HTML export failed: {html_response.status_code}")
    else:
        print("Failed to create mock result")