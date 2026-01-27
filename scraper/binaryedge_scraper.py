#!/usr/bin/env python3
"""
BinaryEdge scraper - Free tier available for security research.
https://console.binaryedge.io/
"""

import os
import json
from datetime import datetime
import requests

BINARYEDGE_BASE_URL = "https://api.binaryedge.io/v2"

def get_api_credentials():
    """Get BinaryEdge API credentials from environment."""
    return os.environ.get('BINARYEDGE_API_KEY', '')

def search_binaryedge(query, api_key=''):
    """Search BinaryEdge for Clawdbot installations."""
    results = []
    
    search_queries = [
        'Clawdbot',
        'product:Clawdbot',
        'port:3000',
        'service:http'
    ]
    
    for sq in search_queries:
        try:
            url = f"{BINARYEDGE_BASE_URL}/query/search"
            params = {'query': sq, 'page': 1, 'size': 20}
            headers = {'X-Key': api_key} if api_key else {}
            
            response = requests.get(url, params=params, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                results.extend(data.get('events', []))
            elif response.status_code == 402:
                # Quota exceeded
                print("BinaryEdge quota exceeded, continuing with other sources...")
                break
        except Exception as e:
            print(f"BinaryEdge search error: {e}")
    
    return results

def parse_binaryedge_result(item):
    """Parse BinaryEdge result to our format."""
    target = item.get('target', {})
    ip = target.get('ip', '')
    port = target.get('port', 0)
    
    # Check for vulnerabilities
    vulns = ['exposed_service']
    risk_score = 50
    
    # Check ports
    if port in [3000, 8080, 5000, 8000]:
        risk_score += 20
        vulns.append('common_port')
    
    # Check for HTTP
    if item.get('protocol') == 'http':
        risk_score += 15
        vulns.append('http_exposed')
    
    risk_score = min(risk_score, 100)
    
    return {
        'ip': ip,
        'port': port,
        'location': {
            'country_name': item.get('country', 'Unknown'),
            'city': item.get('city', 'Unknown')
        },
        'vulns': vulns,
        'risk_score': risk_score,
        'source': 'binaryedge',
        'timestamp': datetime.now().isoformat()
    }

def mock_scan():
    """Generate mock data for demo."""
    return [
        {
            'ip': '178.62.21.234',
            'port': 3000,
            'location': {'country_name': 'Netherlands', 'city': 'Amsterdam'},
            'vulns': ['exposed_api', 'http_only'],
            'risk_score': 72,
            'source': 'binaryedge',
            'timestamp': datetime.now().isoformat()
        },
        {
            'ip': '167.71.185.31',
            'port': 3000,
            'location': {'country_name': 'Singapore', 'city': 'Singapore'},
            'vulns': ['no_auth'],
            'risk_score': 68,
            'source': 'binaryedge',
            'timestamp': datetime.now().isoformat()
        }
    ]

def run_scan():
    """Main scan function."""
    api_key = get_api_credentials()
    
    if api_key:
        print("🔍 Scanning with BinaryEdge API...")
        all_results = search_binaryedge('Clawdbot', api_key)
    else:
        print("⚠️  No BinaryEdge API key. Using mock data.")
        print("   Set BINARYEDGE_API_KEY env var for real scans.")
        all_results = mock_scan()
    
    # Parse results
    results = []
    for item in all_results:
        if isinstance(item, dict):
            parsed = parse_binaryedge_result(item)
            results.append(parsed)
        else:
            results.append(item)
    
    # Save results
    output_file = 'scraper/results.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"✅ Found {len(results)} installations")
    return results

if __name__ == '__main__':
    run_scan()
