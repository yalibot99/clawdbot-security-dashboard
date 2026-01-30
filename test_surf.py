#!/usr/bin/env python3
"""
Test script for surf forecast API and page.
Uses Flask test client - no server needed!
Run: python3 test_surf.py
"""

import sys
import json
from datetime import datetime
from app import app

def test_api_with_client(endpoint, params=None):
    """Test an API endpoint using Flask test client."""
    with app.test_client() as client:
        if params:
            resp = client.get(endpoint, query_string=params)
        else:
            resp = client.get(endpoint)
        return resp


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
        ("/api/surf/forecast", {"lat": 999, "lon": 999}, 400, "Out of range coords"),
    ]
    
    passed = 0
    failed = 0
    
    for endpoint, params, expected_status, desc in tests:
        try:
            resp = test_api_with_client(endpoint, params)
            
            status_symbol = "✅" if resp.status_code == expected_status else "❌"
            print(f"\n{status_symbol} {desc}")
            print(f"   Expected: {expected_status}, Got: {resp.status_code}")
            
            if resp.status_code == expected_status:
                data = resp.get_json()
                if 'error' in data:
                    print(f"   Error msg: {data['error']}")
                elif 'best_time' in data:
                    bt = data.get('best_time', {})
                    print(f"   Best time: {bt.get('time', 'N/A')}")
                    print(f"   Wind: {bt.get('wind_speed', 'N/A')} km/h")
                passed += 1
            else:
                failed += 1
                print(f"   Response: {resp.get_data(as_text=True)[:100]}")
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
            resp = test_api_with_client("/api/surf/multi-day", params)
            
            status_symbol = "✅" if resp.status_code == expected_status else "❌"
            print(f"\n{status_symbol} {desc}")
            print(f"   Expected: {expected_status}, Got: {resp.status_code}")
            
            if resp.status_code == expected_status:
                data = resp.get_json()
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
            resp = test_api_with_client(path)
            
            status_symbol = "✅" if resp.status_code == 200 else "❌"
            print(f"\n{status_symbol} {desc}")
            print(f"   Status: {resp.status_code}")
            
            if resp.status_code == 200:
                content = resp.get_data(as_text=True)
                # Check for essential elements
                checks = [
                    ("best-time", "Best time element"),
                    ("hourly-scroll", "Hourly scroll element"),
                    ("Ayali", "Ayali title"),
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
    exit_code = run_all_tests()
    sys.exit(exit_code)
