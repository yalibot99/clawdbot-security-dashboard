#!/usr/bin/env python3
"""
Test script for surf forecast API and page.
Run: python3 test_surf.py
"""

import sys
import requests
import json
from datetime import datetime

BASE_URL = "http://localhost:5000"

def test_api_endpoint(endpoint, params=None):
    """Test an API endpoint and print results."""
    url = f"{BASE_URL}{endpoint}"
    try:
        if params:
            resp = requests.get(url, params=params, timeout=10)
        else:
            resp = requests.get(url, timeout=10)
        
        print(f"\n🧪 Testing: {endpoint}")
        print(f"   URL: {url}")
        print(f"   Status: {resp.status_code}")
        
        if resp.status_code == 200:
            data = resp.json()
            if 'error' in data:
                print(f"   ❌ Error response: {data['error']}")
                return False
            else:
                print(f"   ✅ Success!")
                return True
        else:
            print(f"   ❌ HTTP Error: {resp.status_code}")
            try:
                print(f"   Response: {resp.text[:200]}")
            except:
                pass
            return False
    except requests.exceptions.ConnectionError:
        print(f"\n🧪 Testing: {endpoint}")
        print(f"   ❌ Connection Error - Is the server running at {BASE_URL}?")
        print(f"   💡 Run: cd /home/ubuntu/clawd/clawdbot-security-dashboard && python3 app.py")
        return False
    except Exception as e:
        print(f"   ❌ Exception: {e}")
        return False


def test_surf_forecast():
    """Test the main surf forecast API."""
    print("\n" + "="*50)
    print("🏄 SURF FORECAST API TESTS")
    print("="*50)
    
    tests = [
        # (endpoint, params, expected_status, description)
        ("/api/surf/forecast", {"lat": 32.0853, "lon": 34.7818}, 200, "Valid Tel Aviv coords"),
        ("/api/surf/forecast", {"lat": 34.0522, "lon": -118.2437}, 200, "Los Angeles"),
        ("/api/surf/forecast", {"lat": -33.8688, "lon": 151.2093}, 200, "Sydney"),
        ("/api/surf/forecast", {}, 400, "Missing lat/lon"),
        ("/api/surf/forecast", {"lat": "abc", "lon": "def"}, 400, "Invalid coords (strings)"),
        ("/api/surf/forecast", {"lat": 999, "lon": 999}, 400, "Out of range coords"),
        ("/api/surf/forecast", {"lat": None, "lon": 34.7818}, 400, "Null lat"),
    ]
    
    passed = 0
    failed = 0
    
    for endpoint, params, expected_status, desc in tests:
        try:
            url = f"{BASE_URL}{endpoint}"
            resp = requests.get(url, params=params, timeout=10)
            
            status_symbol = "✅" if resp.status_code == expected_status else "❌"
            print(f"\n{status_symbol} {desc}")
            print(f"   Expected: {expected_status}, Got: {resp.status_code}")
            
            if resp.status_code == expected_status:
                data = resp.json()
                if 'error' in data:
                    print(f"   Error msg: {data['error']}")
                elif 'best_time' in data:
                    bt = data.get('best_time', {})
                    print(f"   Best time: {bt.get('time', 'N/A')}")
                    print(f"   Wind: {bt.get('wind_speed', 'N/A')} km/h")
                passed += 1
            else:
                failed += 1
                print(f"   Response: {resp.text[:100]}")
        except Exception as e:
            failed += 1
            print(f"   ❌ Exception: {e}")
    
    return passed, failed


def test_multi_day():
    """Test the multi-day forecast API."""
    print("\n" + "="*50)
    print("📅 MULTI-DAY FORECAST API TESTS")
    print("="*50)
    
    tests = [
        ({"lat": 32.0853, "lon": 34.7818}, 200, "Tel Aviv 3-day"),
        ({}, 400, "Missing params"),
    ]
    
    passed = 0
    failed = 0
    
    for params, expected_status, desc in tests:
        try:
            url = f"{BASE_URL}/api/surf/multi-day"
            resp = requests.get(url, params=params, timeout=10)
            
            status_symbol = "✅" if resp.status_code == expected_status else "❌"
            print(f"\n{status_symbol} {desc}")
            print(f"   Expected: {expected_status}, Got: {resp.status_code}")
            
            if resp.status_code == expected_status:
                data = resp.json()
                if 'days' in data:
                    print(f"   Days returned: {len(data.get('days', []))}")
                    if data.get('best_day'):
                        print(f"   Best day: {data['best_day'].get('date', 'N/A')}")
                passed += 1
            else:
                failed += 1
        except Exception as e:
            failed += 1
            print(f"   ❌ Exception: {e}")
    
    return passed, failed


def test_page_loads():
    """Test that the surf page loads correctly."""
    print("\n" + "="*50)
    print("🌐 PAGE LOAD TESTS")
    print("="*50)
    
    pages = [
        ("/surf", "Surf forecast page"),
    ]
    
    passed = 0
    failed = 0
    
    for path, desc in pages:
        try:
            url = f"{BASE_URL}{path}"
            resp = requests.get(url, timeout=10)
            
            status_symbol = "✅" if resp.status_code == 200 else "❌"
            print(f"\n{status_symbol} {desc}")
            print(f"   Status: {resp.status_code}")
            
            if resp.status_code == 200:
                content = resp.text
                # Check for essential elements
                checks = [
                    ("best-time", "Best time element"),
                    ("wind-summary", "Wind summary element"),
                    ("hourly-scroll", "Hourly scroll element"),
                ]
                for element_id, name in checks:
                    if element_id in content:
                        print(f"   ✅ {name} found")
                    else:
                        print(f"   ⚠️ {name} missing")
                passed += 1
            else:
                failed += 1
        except Exception as e:
            failed += 1
            print(f"   ❌ Exception: {e}")
    
    return passed, failed


def run_all_tests():
    """Run all tests and print summary."""
    print("\n" + "="*50)
    print("🧪 AYALI'S WING FOIL FORECAST - TEST SUITE")
    print("="*50)
    print(f"Base URL: {BASE_URL}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Run tests
    sp1, sf1 = test_surf_forecast()
    sp2, sf2 = test_multi_day()
    sp3, sf3 = test_page_loads()
    
    total_passed = sp1 + sp2 + sp3
    total_failed = sf1 + sf2 + sf3
    
    print("\n" + "="*50)
    print("📊 TEST SUMMARY")
    print("="*50)
    print(f"✅ Passed: {total_passed}")
    print(f"❌ Failed: {total_failed}")
    print(f"📈 Total: {total_passed + total_failed}")
    
    if total_failed == 0:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print(f"\n⚠️  {total_failed} test(s) failed")
        return 1


if __name__ == "__main__":
    # Check if server URL provided
    if len(sys.argv) > 1:
        BASE_URL = sys.argv[1]
    
    exit_code = run_all_tests()
    sys.exit(exit_code)
