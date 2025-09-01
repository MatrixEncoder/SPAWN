#!/usr/bin/env python3
"""
Focused test for report export formats
"""

import requests
import json

def test_report_formats():
    """Test the professional report formats"""
    
    base_url = "https://scan-debug-1.preview.emergentagent.com/api"
    
    # Get available results
    results_response = requests.get(f"{base_url}/results")
    if results_response.status_code != 200:
        print("❌ Cannot get results")
        return False
    
    results = results_response.json()
    if not results:
        print("❌ No results available")
        return False
    
    result_id = results[0]["id"]
    print(f"✅ Testing with result: {result_id}")
    
    # Test each export format
    formats = ["json", "csv", "pdf", "html"]
    
    for format_type in formats:
        print(f"\n🔍 Testing {format_type.upper()} export...")
        
        response = requests.get(f"{base_url}/results/{result_id}/export/{format_type}")
        
        if response.status_code == 200:
            content_type = response.headers.get('content-type', '')
            content_length = len(response.content)
            
            print(f"✅ {format_type.upper()} export successful")
            print(f"   Content-Type: {content_type}")
            print(f"   Size: {content_length} bytes")
            
            if format_type == "html":
                content = response.text
                
                # Check for professional report elements
                required_elements = [
                    "Target URL:",
                    "Scan Date:",
                    "Scan Status:",
                    "Total Vulnerabilities:",
                    "Vulnerability Distribution",
                    "SPAWN - Professional Vulnerability Assessment Platform"
                ]
                
                found_elements = []
                missing_elements = []
                
                for element in required_elements:
                    if element in content:
                        found_elements.append(element)
                    else:
                        missing_elements.append(element)
                
                print(f"   ✅ Found elements: {len(found_elements)}/{len(required_elements)}")
                if missing_elements:
                    print(f"   ⚠️  Missing elements: {missing_elements}")
                
                # Check for proper CSS classes
                css_classes = [
                    'class="info-table"',
                    'class="dist-table"',
                    'class="section-title"',
                    'class="footer"'
                ]
                
                css_found = sum(1 for css_class in css_classes if css_class in content)
                print(f"   ✅ CSS structure: {css_found}/{len(css_classes)} classes found")
                
            elif format_type == "csv":
                content = response.text
                
                # Check CSV structure
                csv_elements = [
                    "SPAWN Professional Vulnerability Assessment Report",
                    "Header Information",
                    "Target URL",
                    "Vulnerability Distribution",
                    "Detailed Vulnerability Findings",
                    "#,Type,Severity,URL,Parameter,Description,CWE"
                ]
                
                csv_found = sum(1 for element in csv_elements if element in content)
                print(f"   ✅ CSV structure: {csv_found}/{len(csv_elements)} elements found")
                
                if csv_found < len(csv_elements):
                    missing_csv = [elem for elem in csv_elements if elem not in content]
                    print(f"   ⚠️  Missing CSV elements: {missing_csv}")
            
            elif format_type == "json":
                try:
                    data = response.json()
                    if "scan_result" in data and "scan_config" in data:
                        print(f"   ✅ JSON structure valid")
                    else:
                        print(f"   ⚠️  JSON structure incomplete")
                except:
                    print(f"   ❌ Invalid JSON")
            
            elif format_type == "pdf":
                if content_length > 1000:
                    print(f"   ✅ PDF appears to be properly generated")
                else:
                    print(f"   ⚠️  PDF size seems small: {content_length} bytes")
        else:
            print(f"❌ {format_type.upper()} export failed: HTTP {response.status_code}")
    
    return True

if __name__ == "__main__":
    print("🎯 SPAWN Report Format Testing")
    print("=" * 50)
    
    success = test_report_formats()
    
    if success:
        print("\n✅ Report format testing completed")
    else:
        print("\n❌ Report format testing failed")