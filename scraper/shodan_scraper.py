#!/usr/bin/env python3
"""
Shodan scraper for discovering accessible Clawdbot installations.
"""

import os
import json
import time
from datetime import datetime

try:
    import shodan
except ImportError:
    shodan = None

# Clawdbot default ports and signatures
CLAWDBOT_PORTS = [3000, 8080, 5000, 8000]
SIGNATURES = ['clawdbot', 'Clawdbot', 'gateway', 'api/health', 'socket.io']

def get_api_key():
    return os.environ.get('SHODAN_API_KEY', '')

def search_clawdbot(api, query='clawdbot'):
    """Search Shodan for Clawdbot installations."""
    results = []
    try:
        for banner in api.search_cursor(query):
            results.append(banner)
            if len(results) >= 50:  # Limit for demo
                break
    except Exception as e:
        print(f"Search error: {e}")
    return results

def mock_scan():
    """Generate mock data for demo purposes."""
    return [
        {
            'ip': '192.168.1.100',
            'port': 3000,
            'location': {'country_name': 'Israel', 'city': 'Tel Aviv'},
            'vulns': ['exposed_api', 'no_auth'],
            'risk_score': 85,
            'timestamp': datetime.now().isoformat()
        },
        {
            'ip': '10.0.0.55',
            'port': 3000,
            'location': {'country_name': 'United States', 'city': 'New York'},
            'vulns': ['default_creds', 'exposed_terminal'],
            'risk_score': 92,
            'timestamp': datetime.now().isoformat()
        },
        {
            'ip': '172.16.0.23',
            'port': 8080,
            'location': {'country_name': 'Germany', 'city': 'Berlin'},
            'vulns': ['outdated_version'],
            'risk_score': 45,
            'timestamp': datetime.now().isoformat()
        },
    ]

def run_scan():
    """Main scan function."""
    api_key = get_api_key()
    
    if api_key and shodan:
        print(f"🔍 Scanning with Shodan API...")
        api = shodan.Shodan(api_key)
        results = search_clawdbot(api)
    else:
        print(f"⚠️  No Shodan API key. Using mock data for demo.")
        print("   Set SHODAN_API_KEY env var for real scans.")
        results = mock_scan()
    
    # Save results
    output_file = 'scraper/results.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"✅ Found {len(results)} installations")
    print(f"   Results saved to {output_file}")
    return results

if __name__ == '__main__':
    run_scan()
