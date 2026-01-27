#!/usr/bin/env python3
"""
Censys scraper for discovering accessible Clawdbot installations.
Free alternative to Shodan.
"""

import os
import json
from datetime import datetime
import requests

try:
    import censys
except ImportError:
    censys = None

# Clawdbot search queries for Censys
CENSYS_QUERIES = [
    'services.http.response.html_title:"Clawdbot Gateway"',
    'services.http.response.html_title:"gateway"',
    'services.port: 3000',
    'services.http.response.headers.x_powered_by:"Express"',
]

def get_api_credentials():
    """Get Censys API credentials from environment."""
    return os.environ.get('CENSYS_API_ID', ''), os.environ.get('CENSYS_API_SECRET', '')

def search_censys(api_id, api_secret, query):
    """Search Censys for Clawdbot installations."""
    results = []
    try:
        if censys:
            # Using censys-python library
            census = censys.CensysHosts(api_id=api_id, api_secret=api_secret)
            for host in census.search(query, per_page=20):
                results.append(host)
                if len(results) >= 50:
                    break
        else:
            # Direct API call
            url = "https://censys.io/api/v1/search/ipv4"
            auth = (api_id, api_secret)
            payload = {"query": query, "per_page": 20}
            resp = requests.post(url, json=payload, auth=auth)
            if resp.status_code == 200:
                data = resp.json()
                results = data.get('results', [])
    except Exception as e:
        print(f"Censys search error: {e}")
    return results

def parse_censys_result(host):
    """Parse Censys result to our format."""
    ip = host.get('ip', '')
    services = host.get('services', [])
    
    # Find Clawdbot-related services
    clawdbot_services = []
    for svc in services:
        port = svc.get('port', 0)
        if port in [3000, 8080, 5000, 8000]:
            clawdbot_services.append(svc)
    
    if not clawdbot_services:
        return None
    
    # Extract location
    location = host.get('location', {})
    country = location.get('country', 'Unknown')
    city = location.get('city', 'Unknown')
    
    # Calculate risk score
    risk_score = 50
    for svc in clawdbot_services:
        if svc.get('transport') == 'http':
            risk_score += 20
        if svc.get('tls') is False:
            risk_score += 15
    
    risk_score = min(risk_score, 100)
    
    return {
        'ip': ip,
        'port': clawdbot_services[0].get('port', 0),
        'location': {'country_name': country, 'city': city},
        'vulns': ['exposed_service'],
        'risk_score': risk_score,
        'timestamp': datetime.now().isoformat()
    }

def mock_scan():
    """Generate mock data for demo."""
    return [
        {
            'ip': '185.220.101.42',
            'port': 3000,
            'location': {'country_name': 'Germany', 'city': 'Frankfurt'},
            'vulns': ['exposed_api', 'http_only'],
            'risk_score': 78,
            'timestamp': datetime.now().isoformat()
        },
        {
            'ip': '91.207.174.23',
            'port': 3000,
            'location': {'country_name': 'Russia', 'city': 'Moscow'},
            'vulns': ['exposed_gateway'],
            'risk_score': 65,
            'timestamp': datetime.now().isoformat()
        },
        {
            'ip': '203.0.113.50',
            'port': 8080,
            'location': {'country_name': 'United States', 'city': 'San Francisco'},
            'vulns': ['outdated_version'],
            'risk_score': 42,
            'timestamp': datetime.now().isoformat()
        },
    ]

def run_scan():
    """Main scan function."""
    api_id, api_secret = get_api_credentials()
    
    if api_id and api_secret:
        print(f"🔍 Scanning with Censys API...")
        all_results = []
        for query in CENSYS_QUERIES:
            results = search_censys(api_id, api_secret, query)
            for host in results:
                parsed = parse_censys_result(host)
                if parsed:
                    all_results.append(parsed)
        results = all_results[:50]
    else:
        print(f"⚠️  No Censys API credentials. Using mock data.")
        print("   Set CENSYS_API_ID and CENSYS_API_SECRET env vars for real scans.")
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
