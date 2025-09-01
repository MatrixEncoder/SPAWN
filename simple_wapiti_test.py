#!/usr/bin/env python3
"""
Simple Wapiti Path Detection Test
Tests the get_wapiti_command() function and basic scan functionality
"""

import sys
import os
import requests
import json
import time

# Add backend to path
sys.path.append('/app/backend')

def test_wapiti_path_detection():
    """Test the get_wapiti_command() function"""
    print("🎯 TESTING WAPITI PATH DETECTION")
    print("=" * 50)
    
    try:
        from server import get_wapiti_command
        
        # Test the Wapiti path detection
        wapiti_path = get_wapiti_command()
        print(f"Detected Wapiti Path: {wapiti_path}")
        
        # Verify the path exists and is executable
        if wapiti_path == "wapiti":
            # Check if wapiti is in PATH
            import subprocess
            try:
                result = subprocess.run(["which", "wapiti"], capture_output=True, text=True)
                if result.returncode == 0:
                    actual_path = result.stdout.strip()
                    print(f"✅ Wapiti found in PATH: {actual_path}")
                    return True
                else:
                    print("❌ Wapiti command not found in PATH")
                    return False
            except Exception as e:
                print(f"❌ Error checking PATH: {str(e)}")
                return False
        else:
            # Check if the specific path exists
            if os.path.exists(wapiti_path):
                # Check if it's executable
                if os.access(wapiti_path, os.X_OK):
                    print(f"✅ Wapiti executable found: {wapiti_path}")
                    return True
                else:
                    print(f"❌ Wapiti path exists but not executable: {wapiti_path}")
                    return False
            else:
                print(f"❌ Wapiti path does not exist: {wapiti_path}")
                return False
                
    except ImportError as e:
        print(f"❌ Cannot import get_wapiti_command function: {str(e)}")
        return False
    except Exception as e:
        print(f"❌ Error testing Wapiti path detection: {str(e)}")
        return False

def test_basic_api_connectivity():
    """Test basic API connectivity"""
    print("\n🎯 TESTING API CONNECTIVITY")
    print("=" * 50)
    
    try:
        base_url = "https://scan-debug-1.preview.emergentagent.com/api"
        response = requests.get(f"{base_url}/", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if "message" in data and "SPAWN" in data["message"]:
                print("✅ API connectivity working")
                return True
            else:
                print(f"❌ Unexpected API response: {data}")
                return False
        else:
            print(f"❌ API returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ API connectivity error: {str(e)}")
        return False

def test_scan_creation():
    """Test scan configuration creation"""
    print("\n🎯 TESTING SCAN CREATION")
    print("=" * 50)
    
    try:
        base_url = "https://scan-debug-1.preview.emergentagent.com/api"
        
        scan_config = {
            "name": "Simple Wapiti Test",
            "target_url": "http://testphp.vulnweb.com",
            "scan_type": "quick",
            "scope": "folder",
            "depth": 3,
            "level": 1,
            "timeout": 30,
            "verify_ssl": False
        }
        
        response = requests.post(
            f"{base_url}/scans",
            json=scan_config,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            scan_id = data.get("id")
            print(f"✅ Scan created successfully: {scan_id}")
            
            # Try to start the scan
            start_response = requests.post(f"{base_url}/scans/{scan_id}/start", timeout=10)
            if start_response.status_code == 200:
                start_data = start_response.json()
                result_id = start_data.get("result_id")
                print(f"✅ Scan started successfully: {result_id}")
                
                # Wait a moment and check status
                time.sleep(5)
                result_response = requests.get(f"{base_url}/results/{result_id}", timeout=10)
                if result_response.status_code == 200:
                    result_data = result_response.json()
                    status = result_data.get("status")
                    progress = result_data.get("progress", 0)
                    error_message = result_data.get("error_message", "")
                    
                    print(f"Scan Status: {status}")
                    print(f"Progress: {progress}%")
                    
                    if error_message:
                        if "wapiti" in error_message.lower() and ("not found" in error_message.lower() or "no such file" in error_message.lower()):
                            print(f"❌ Wapiti path error: {error_message}")
                            return False
                        else:
                            print(f"⚠️  Scan error (not path related): {error_message}")
                    
                    if status in ["running", "completed"] or progress > 0:
                        print("✅ Scan execution started without path errors")
                        return True
                    else:
                        print(f"❌ Scan not running properly: {status}")
                        return False
                else:
                    print(f"❌ Cannot check scan result: {result_response.status_code}")
                    return False
            else:
                print(f"❌ Cannot start scan: {start_response.status_code}")
                return False
        else:
            print(f"❌ Cannot create scan: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Scan creation error: {str(e)}")
        return False

def main():
    """Main test execution"""
    print("🔍 SIMPLE WAPITI PATH DETECTION TEST")
    print("=" * 60)
    
    results = []
    
    # Test 1: Wapiti path detection
    results.append(test_wapiti_path_detection())
    
    # Test 2: API connectivity
    results.append(test_basic_api_connectivity())
    
    # Test 3: Scan creation and execution
    results.append(test_scan_creation())
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(results)
    total = len(results)
    
    print(f"Tests Passed: {passed}/{total}")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("\n🎉 All Wapiti path tests passed!")
        print("✅ Wapiti path detection is working correctly")
        print("✅ Scan creation works without path errors")
        print("✅ Scan execution starts without path errors")
        return True
    else:
        print(f"\n💥 {total-passed} test(s) failed!")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)