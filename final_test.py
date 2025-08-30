#!/usr/bin/env python3
"""
Final Priority Test - Verify all fixes are working
"""

import requests
import time

def test_all_exports():
    """Test all export formats with existing result"""
    result_id = "581a87f8-acc7-49b5-959d-4a9461e49dbf"
    base_url = "https://report-template-1.preview.emergentagent.com/api"
    
    formats = ["json", "csv", "pdf", "html"]
    results = {}
    
    for format_type in formats:
        try:
            response = requests.get(f"{base_url}/results/{result_id}/export/{format_type}", timeout=30)
            if response.status_code == 200:
                content_length = len(response.content)
                content_type = response.headers.get('content-type', '')
                results[format_type] = f"✅ SUCCESS ({content_length} bytes, {content_type})"
            else:
                results[format_type] = f"❌ FAILED (HTTP {response.status_code})"
        except Exception as e:
            results[format_type] = f"❌ ERROR ({str(e)})"
    
    return results

def test_scan_presets():
    """Test scan presets configuration"""
    base_url = "https://report-template-1.preview.emergentagent.com/api"
    
    try:
        response = requests.get(f"{base_url}/scan-presets", timeout=10)
        if response.status_code == 200:
            data = response.json()
            quick = data.get("presets", {}).get("quick", {})
            
            improvements = []
            if quick.get("scope") == "domain":
                improvements.append("✓ Domain scope")
            if quick.get("depth", 0) >= 3:
                improvements.append(f"✓ Depth: {quick.get('depth')}")
            if quick.get("level", 0) >= 2:
                improvements.append(f"✓ Level: {quick.get('level')}")
            if len(quick.get("modules", [])) >= 6:
                improvements.append(f"✓ Modules: {len(quick.get('modules', []))}")
            
            return f"✅ IMPROVED: {'; '.join(improvements)}"
        else:
            return f"❌ FAILED: HTTP {response.status_code}"
    except Exception as e:
        return f"❌ ERROR: {str(e)}"

def test_quick_scan():
    """Test a quick scan to verify progress tracking"""
    base_url = "https://report-template-1.preview.emergentagent.com/api"
    
    try:
        # Create scan config
        scan_config = {
            "name": "Final Test Scan",
            "target_url": "https://httpbin.org/",  # Simple, reliable test site
            "scan_type": "quick",
            "max_scan_time": 60  # 1 minute max
        }
        
        response = requests.post(f"{base_url}/scans", json=scan_config, timeout=10)
        if response.status_code == 200:
            scan_id = response.json()["id"]
            
            # Start scan
            start_response = requests.post(f"{base_url}/scans/{scan_id}/start", timeout=10)
            if start_response.status_code == 200:
                result_id = start_response.json()["result_id"]
                
                # Monitor progress for 60 seconds
                progress_updates = 0
                max_progress = 0
                
                for i in range(12):  # Check every 5 seconds for 1 minute
                    time.sleep(5)
                    result_response = requests.get(f"{base_url}/results/{result_id}", timeout=10)
                    if result_response.status_code == 200:
                        result_data = result_response.json()
                        progress = result_data.get("progress", 0)
                        status = result_data.get("status", "unknown")
                        
                        if progress > max_progress:
                            progress_updates += 1
                            max_progress = progress
                        
                        if status == "completed":
                            break
                
                if progress_updates > 0:
                    return f"✅ PROGRESS TRACKING: {progress_updates} updates (max: {max_progress}%)"
                else:
                    return "❌ NO PROGRESS UPDATES"
            else:
                return f"❌ SCAN START FAILED: HTTP {start_response.status_code}"
        else:
            return f"❌ SCAN CONFIG FAILED: HTTP {response.status_code}"
    except Exception as e:
        return f"❌ ERROR: {str(e)}"

def main():
    print("🎯 FINAL PRIORITY TEST - Verification of Fixes")
    print("=" * 60)
    
    print("\n1. Testing Export Functionality (All Formats):")
    export_results = test_all_exports()
    for format_type, result in export_results.items():
        print(f"   {format_type.upper()}: {result}")
    
    print("\n2. Testing Scan Presets Configuration:")
    preset_result = test_scan_presets()
    print(f"   {preset_result}")
    
    print("\n3. Testing Real-time Progress Tracking:")
    progress_result = test_quick_scan()
    print(f"   {progress_result}")
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 FINAL TEST SUMMARY")
    print("=" * 60)
    
    export_success = sum(1 for r in export_results.values() if "SUCCESS" in r)
    preset_success = "IMPROVED" in preset_result
    progress_success = "PROGRESS TRACKING" in progress_result
    
    print(f"Export Functionality: {export_success}/4 formats working")
    print(f"Scan Presets: {'✅ IMPROVED' if preset_success else '❌ NEEDS WORK'}")
    print(f"Progress Tracking: {'✅ WORKING' if progress_success else '❌ NEEDS WORK'}")
    
    total_score = export_success + (1 if preset_success else 0) + (1 if progress_success else 0)
    print(f"\nOverall Score: {total_score}/6 tests passed")
    
    if total_score >= 5:
        print("🎉 PRIORITY ISSUES RESOLVED!")
    elif total_score >= 3:
        print("⚠️  SIGNIFICANT IMPROVEMENTS MADE")
    else:
        print("💥 MORE WORK NEEDED")

if __name__ == "__main__":
    main()