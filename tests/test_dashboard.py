#!/usr/bin/env python3
"""
Comprehensive test suite for Clawdbot Security Dashboard.
Tests API connectivity, fingerprinting, and data collection.
"""

import os
import sys
import json
import requests
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the app for testing
from app import app, CENSYS_API_ID, CENSYS_API_SECRET, search_censys, fingerprint_clawdbot, calculate_risk_score

def test_api_connection():
    """Test if Censys API credentials are valid."""
    print("\n" + "="*60)
    print("🧪 TEST: API Connection")
    print("="*60)
    
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        print("❌ FAILED: API credentials not configured")
        print("   Set CENSYS_API_ID and CENSYS_API_SECRET environment variables")
        return False
    
    url = "https://search.censys.io/api/v2/hosts/search?q=18789&per_page=1"
    auth = (CENSYS_API_ID, CENSYS_API_SECRET)
    
    try:
        response = requests.get(url, auth=auth, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            hits = data.get('result', {}).get('hits', [])
            print(f"✅ PASSED: API connection successful")
            print(f"   Response: {len(hits)} hosts found for test query")
            return True
        elif response.status_code == 401:
            print(f"❌ FAILED: Invalid API credentials (401 Unauthorized)")
            print("   Check your CENSYS_API_ID and CENSYS_API_SECRET")
            return False
        else:
            print(f"❌ FAILED: API returned status {response.status_code}")
            print(f"   Response: {response.text[:200]}")
            return False
            
    except Exception as e:
        print(f"❌ FAILED: Connection error: {e}")
        return False

def test_fingerprinting():
    """Test the fingerprinting function with known endpoints."""
    print("\n" + "="*60)
    print("🧪 TEST: Service Fingerprinting")
    print("="*60)
    
    # Test with a known non-Clawdbot endpoint (should return False)
    test_cases = [
        {"ip": "1.1.1.1", "port": 80, "expected_clawdbot": False, "description": "Cloudflare DNS"},
        {"ip": "8.8.8.8", "port": 443, "expected_clawdbot": False, "description": "Google DNS"},
    ]
    
    passed = 0
    failed = 0
    
    for test in test_cases:
        is_clawdbot, vulns, service_info = fingerprint_clawdbot(test["ip"], test["port"])
        
        if is_clawdbot == test["expected_clawdbot"]:
            print(f"✅ PASSED: {test['description']} ({test['ip']}:{test['port']})")
            print(f"   Result: {'Clawdbot' if is_clawdbot else 'Not Clawdbot'} (expected)")
            passed += 1
        else:
            print(f"❌ FAILED: {test['description']} ({test['ip']}:{test['port']})")
            print(f"   Result: {'Clawdbot' if is_clawdbot else 'Not Clawdbot'} (expected: {'Clawdbot' if test['expected_clawdbot'] else 'Not Clawdbot'})")
            failed += 1
    
    if failed == 0:
        print(f"\n✅ All fingerprinting tests passed ({passed}/{passed})")
        return True
    else:
        print(f"\n❌ Some tests failed ({passed}/{passed+failed})")
        return False

def test_risk_score_calculation():
    """Test risk score calculation logic."""
    print("\n" + "="*60)
    print("🧪 TEST: Risk Score Calculation")
    print("="*60)
    
    test_cases = [
        {
            "vulns": ["no_auth", "exposed_api"],
            "expected_min": 70,
            "expected_max": 100,
            "description": "No auth + exposed API"
        },
        {
            "vulns": ["exposed_terminal"],
            "expected_min": 70,
            "expected_max": 100,
            "description": "Exposed terminal"
        },
        {
            "vulns": ["outdated_version"],
            "expected_min": 50,
            "expected_max": 70,
            "description": "Outdated version only"
        },
        {
            "vulns": [],
            "expected_min": 50,
            "expected_max": 50,
            "description": "No vulnerabilities"
        }
    ]
    
    passed = 0
    failed = 0
    
    for test in test_cases:
        score = calculate_risk_score(test["vulns"])
        
        if test["expected_min"] <= score <= test["expected_max"]:
            print(f"✅ PASSED: {test['description']}")
            print(f"   Score: {score} (expected: {test['expected_min']}-{test['expected_max']})")
            passed += 1
        else:
            print(f"❌ FAILED: {test['description']}")
            print(f"   Score: {score} (expected: {test['expected_min']}-{test['expected_max']})")
            failed += 1
    
    if failed == 0:
        print(f"\n✅ All risk score tests passed ({passed}/{passed})")
        return True
    else:
        print(f"\n❌ Some tests failed ({passed}/{passed+failed})")
        return False

def test_censys_search():
    """Test Censys search and fingerprinting."""
    print("\n" + "="*60)
    print("🧪 TEST: Censys Search & Fingerprinting")
    print("="*60)
    
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        print("⚠️  SKIPPED: API credentials not configured")
        return None
    
    print("   Searching for Clawdbot-related ports...")
    results = search_censys()
    
    if results is None:
        print("❌ FAILED: Censys search returned error")
        return False
    
    print(f"   Scan complete. Found {len(results)} verified installations.")
    
    if len(results) > 0:
        print("\n✅ PASSED: Found Clawdbot installations:")
        for r in results[:5]:  # Show first 5
            print(f"   - {r['ip']}:{r['port']} ({r['location'].get('country_name', 'Unknown')})")
            print(f"     Risk: {r['risk_score']}, Vulns: {r['vulns']}")
    else:
        print("\n⚠️  WARNING: No verified installations found")
        print("   This could mean:")
        print("   1. No actual Clawdbot instances are exposed on scanned ports")
        print("   2. Censys rate limits have been reached")
        print("   3. The fingerprinting is too strict")
    
    return len(results) > 0

def test_flask_endpoints():
    """Test Flask API endpoints."""
    print("\n" + "="*60)
    print("🧪 TEST: Flask API Endpoints")
    print("="*60)
    
    # Use test client
    with app.test_client() as client:
        # Test /api/health
        response = client.get('/api/health')
        if response.status_code == 200:
            print("✅ PASSED: /api/health endpoint")
        else:
            print(f"❌ FAILED: /api/health returned {response.status_code}")
        
        # Test /api/stats
        response = client.get('/api/stats')
        if response.status_code == 200:
            data = json.loads(response.data)
            print("✅ PASSED: /api/stats endpoint")
            print(f"   Total findings: {data.get('total', 0)}")
            print(f"   API connected: {data.get('api_connected', False)}")
        else:
            print(f"❌ FAILED: /api/stats returned {response.status_code}")
        
        # Test /api/results
        response = client.get('/api/results')
        if response.status_code == 200:
            data = json.loads(response.data)
            print("✅ PASSED: /api/results endpoint")
            print(f"   Results count: {len(data)}")
        else:
            print(f"❌ FAILED: /api/results returned {response.status_code}")
        
        # Test /api/scan (only if API configured)
        if CENSYS_API_ID and CENSYS_API_SECRET:
            response = client.post('/api/scan')
            if response.status_code == 200:
                data = json.loads(response.data)
                print("✅ PASSED: /api/scan endpoint")
                print(f"   Status: {data.get('status')}")
                print(f"   Found: {data.get('total_found', 0)} installations")
            else:
                print(f"❌ FAILED: /api/scan returned {response.status_code}")
        else:
            print("⚠️  SKIPPED: /api/scan (API not configured)")

def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("🚀 Clawdbot Security Dashboard - Test Suite")
    print("="*60)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Censys API: {'✅ Configured' if CENSYS_API_ID else '❌ Not configured'}")
    
    results = {
        "api_connection": test_api_connection(),
        "fingerprinting": test_fingerprinting(),
        "risk_score": test_risk_score_calculation(),
        "censys_search": test_censys_search(),
        "flask_endpoints": test_flask_endpoints()
    }
    
    print("\n" + "="*60)
    print("📊 TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for v in results.values() if v == True)
    failed = sum(1 for v in results.values() if v == False)
    skipped = sum(1 for v in results.values() if v is None)
    
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Skipped: {skipped}")
    
    if failed == 0:
        print("\n✅ All tests passed!")
        return 0
    else:
        print(f"\n❌ {failed} test(s) failed")
        return 1

if __name__ == '__main__':
    sys.exit(main())
