#!/usr/bin/env python3
"""
Standalone test for Censys API connection.
Run with environment variables:
  CENSYS_API_ID=xxx CENSYS_API_SECRET=yyy python3 test_api_standalone.py
"""

import os
import sys
import requests
from requests.auth import HTTPBasicAuth

# Get API credentials from environment
API_ID = os.environ.get('CENSYS_API_ID', '')
API_SECRET = os.environ.get('CENSYS_API_SECRET', '')

print("="*60)
print("🔑 Censys API Test")
print("="*60)
print(f"API ID: {API_ID[:10] if API_ID else 'NOT SET'}...")
print(f"API Secret: {'*' * 20 if API_SECRET else 'NOT SET'}")

if not API_ID or not API_SECRET:
    print("\n❌ ERROR: API credentials not set!")
    print("Set environment variables:")
    print("  export CENSYS_API_ID=your_id")
    print("  export CENSYS_API_SECRET=your_secret")
    sys.exit(1)

# Test 1: Simple search query
print("\n📡 Test 1: Search for port 3000...")
url = "https://search.censys.io/api/v2/hosts/search?q=port:3000&per_page=5"
auth = HTTPBasicAuth(API_ID, API_SECRET)

try:
    resp = requests.get(url, auth=auth, timeout=30)
    print(f"   Status: {resp.status_code}")
    
    if resp.status_code == 200:
        data = resp.json()
        hits = data.get('result', {}).get('hits', [])
        print(f"   ✅ SUCCESS! Found {len(hits)} hosts")
        for h in hits[:3]:
            port = h.get('services', [{}])[0].get('port', '?')
            print(f"      - {h.get('ip')}:{port}")
    elif resp.status_code == 401:
        print(f"   ❌ FAILED: 401 Unauthorized")
        print(f"   Response: {resp.text[:200]}")
        print("\n💡 Tips:")
        print("   - Check if the token is valid on https://search.censys.io/account")
        print("   - Try generating a new token")
        print("   - Make sure the account is active")
    else:
        print(f"   ❌ FAILED: Status {resp.status_code}")
        print(f"   Response: {resp.text[:200]}")
        
except Exception as e:
    print(f"   ❌ ERROR: {e}")

# Test 2: Search for specific Clawdbot ports
print("\n📡 Test 2: Search for Clawdbot ports (18789, 18791)...")
for port in ['18789', '18791']:
    url = f"https://search.censys.io/api/v2/hosts/search?q=port:{port}&per_page=3"
    try:
        resp = requests.get(url, auth=auth, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            hits = data.get('result', {}).get('hits', [])
            print(f"   Port {port}: {len(hits)} hosts")
        else:
            print(f"   Port {port}: Error {resp.status_code}")
    except Exception as e:
        print(f"   Port {port}: {e}")

# Test 3: Try Censys Python library
print("\n📦 Test 3: Check if censys library is available...")
try:
    import censys
    print("   ✅ censys library installed")
    print(f"   Version: {censys.__version__ if hasattr(censys, '__version__') else 'unknown'}")
except ImportError as e:
    print(f"   ⚠️  censys library not installed: {e}")
    print("   Install with: pip install censys")

print("\n" + "="*60)
print("Done!")
print("="*60)
