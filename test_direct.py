#!/usr/bin/env python3
"""
Direct test of Censys API with credentials.
"""

import requests
from requests.auth import HTTPBasicAuth

# Hardcoded credentials (from Eyal)
API_ID = "Q8MvuXQb"
API_SECRET = "7keQK5JtchFfuuVKxGWTkTRZ"

print("Testing Censys API...")
print(f"API ID: {API_ID}")
print(f"API Secret: {API_SECRET[:10]}...")

auth = HTTPBasicAuth(API_ID, API_SECRET)

# Test account endpoint
print("\n1. Testing account endpoint...")
try:
    resp = requests.get(
        "https://search.censys.io/api/v2/account",
        auth=auth,
        timeout=30
    )
    print(f"   Status: {resp.status_code}")
    print(f"   Response: {resp.text[:200]}")
except Exception as e:
    print(f"   Error: {e}")

# Test search endpoint
print("\n2. Testing search for port 3000...")
try:
    resp = requests.get(
        "https://search.censys.io/api/v2/hosts/search?q=port:3000&per_page=3",
        auth=auth,
        timeout=30
    )
    print(f"   Status: {resp.status_code}")
    
    if resp.status_code == 200:
        import json
        data = resp.json()
        hits = data.get('result', {}).get('hits', [])
        print(f"   SUCCESS! Found {len(hits)} hosts")
        for h in hits[:3]:
            print(f"      - {h.get('ip')}")
    else:
        print(f"   Response: {resp.text[:200]}")
        
except Exception as e:
    print(f"   Error: {e}")

# Test search for Clawdbot-specific ports
print("\n3. Testing search for Clawdbot ports...")
for port in ["18789", "18791"]:
    try:
        resp = requests.get(
            f"https://search.censys.io/api/v2/hosts/search?q=port:{port}&per_page=3",
            auth=auth,
            timeout=30
        )
        if resp.status_code == 200:
            data = resp.json()
            hits = len(data.get('result', {}).get('hits', []))
            print(f"   Port {port}: {hits} hosts")
        else:
            print(f"   Port {port}: Error {resp.status_code}")
    except Exception as e:
        print(f"   Port {port}: {e}")

print("\nDone!")
