#!/usr/bin/env python3
"""
Test script to debug Censys integration and fingerprinting.
Run locally with API keys configured.
"""

import os
import requests
from datetime import datetime

# Configuration
CENSYS_API_ID = os.environ.get('CENSYS_API_ID', '7gKjBEGz')
CENSYS_API_SECRET = os.environ.get('CENSYS_API_SECRET', '33MCyBd8i1PNkmsBEPseK6M8')

REQUEST_TIMEOUT = 3

def fingerprint_clawdbot(ip, port):
    """Actively fingerprint a service to verify it's Clawdbot."""
    base_url = f"http://{ip}:{port}"
    vulns = []
    service_info = {}
    
    print(f"\n🔍 Fingerprinting {ip}:{port}...")
    
    # Check 1: Gateway API health endpoint
    try:
        response = requests.get(f"{base_url}/api/health", timeout=REQUEST_TIMEOUT)
        print(f"  /api/health: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'ok':
                vulns.append('exposed_api')
                service_info['gateway'] = True
                print(f"    ✓ Gateway detected")
    except Exception as e:
        print(f"  /api/health: Failed - {type(e).__name__}")
    
    # Check 2: Gateway status endpoint
    try:
        response = requests.get(f"{base_url}/api/status", timeout=REQUEST_TIMEOUT)
        print(f"  /api/status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            service_info['version'] = data.get('version', 'unknown')
            if not data.get('auth', {}).get('enabled'):
                vulns.append('no_auth')
            print(f"    ✓ Status endpoint accessible")
    except Exception as e:
        print(f"  /api/status: Failed - {type(e).__name__}")
    
    # Check 3: Web UI
    try:
        response = requests.get(base_url, timeout=REQUEST_TIMEOUT)
        print(f"  / (web): {response.status_code}")
        if response.status_code == 200:
            content = response.text.lower()
            if 'clawdbot' in content or 'claude' in content:
                service_info['web_ui'] = True
                print(f"    ✓ Clawdbot web UI detected")
            else:
                print(f"    ✗ No Clawdbot markers in HTML")
    except Exception as e:
        print(f"  / (web): Failed - {type(e).__name__}")
    
    is_clawdbot = bool(service_info)
    print(f"  Result: {'✓ CLAWDBOT' if is_clawdbot else '✗ NOT CLAWDBOT'}")
    print(f"  Vulnerabilities: {vulns}")
    
    return is_clawdbot, vulns, service_info

def search_censys(query, service_name):
    """Search Censys and fingerprint results."""
    print(f"\n{'='*60}")
    print(f"🔍 Searching Censys for: {service_name} (port {query})")
    print(f"{'='*60}")
    
    url = f"https://search.censys.io/api/v2/hosts/search?q={query}&per_page=10"
    auth = (CENSYS_API_ID, CENSYS_API_SECRET)
    
    try:
        response = requests.get(url, auth=auth, timeout=30)
        print(f"Status: {response.status_code}")
        
        if response.status_code != 200:
            print(f"Error: {response.text}")
            return []
        
        data = response.json()
        hits = data.get('result', {}).get('hits', [])
        print(f"Found {len(hits)} hosts with port {query}")
        
        verified = []
        for hit in hits:
            ip = hit.get('ip', 'unknown')
            location = hit.get('location', {})
            
            # Get the port
            services = hit.get('services', [])
            port = services[0].get('port', int(query)) if services else int(query)
            
            print(f"\n  Host: {ip}:{port}")
            print(f"  Location: {location.get('city', 'Unknown')}, {location.get('country', 'Unknown')}")
            
            # Fingerprint
            is_clawdbot, vulns, service_info = fingerprint_clawdbot(ip, port)
            
            if is_clawdbot:
                verified.append({
                    'ip': ip,
                    'port': port,
                    'location': location,
                    'vulns': vulns,
                    'service_info': service_info
                })
        
        return verified
        
    except Exception as e:
        print(f"Error: {e}")
        return []

def main():
    print(f"\n{'='*60}")
    print(f"🚀 Clawdbot Security Dashboard - Test Script")
    print(f"{'='*60}")
    print(f"API ID: {CENSYS_API_ID[:10]}...")
    print(f"Timestamp: {datetime.now().isoformat()}")
    
    all_results = []
    
    # Search for Clawdbot ports
    queries = [
        ("18789", "Clawdbot Gateway"),
        ("3000", "Clawdbot Web UI"),
        ("18791", "Clawdbot Browser Control"),
    ]
    
    for query, service_name in queries:
        results = search_censys(query, service_name)
        all_results.extend(results)
    
    print(f"\n{'='*60}")
    print(f"📊 SUMMARY")
    print(f"{'='*60}")
    print(f"Total hosts found by Censys: {sum(len(search_censys(q, s) or []) for q, s in queries)}")
    print(f"Verified Clawdbot installations: {len(all_results)}")
    
    if all_results:
        print(f"\n✅ Verified Installations:")
        for r in all_results:
            print(f"  - {r['ip']}:{r['port']} - {r['location'].get('city', 'Unknown')}, {r['location'].get('country', 'Unknown')}")
    else:
        print(f"\n⚠️  No verified Clawdbot installations found.")
        print(f"\nThis could mean:")
        print(f"  1. No actual Clawdbot instances are exposed on these ports")
        print(f"  2. Censys is returning hosts but they're not Clawdbot")
        print(f"  3. The fingerprinting is too strict")
        print(f"\nTo debug, check the individual fingerprint results above.")

if __name__ == '__main__':
    main()
