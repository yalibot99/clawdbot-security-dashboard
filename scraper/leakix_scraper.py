#!/usr/bin/env python3
"""
LeakIX scraper - Free service for finding exposed services.
https://leakix.net/
"""

import os
import json
from datetime import datetime
import requests

LEAKIX_BASE_URL = "https://leakix.net"

def get_api_credentials():
    """Get LeakIX API credentials from environment."""
    return os.environ.get('LEAKIX_API_KEY', '')

def search_leakix(query, api_key=''):
    """Search LeakIX for Clawdbot installations."""
    results = []
    
    # Search queries for Clawdbot
    search_queries = [
        'Clawdbot',
        'gateway',
        'port:3000'
    ]
    
    for sq in search_queries:
        try:
            url = f"{LEAKIX_BASE_URL}/search"
            params = {'q': sq, 'page': 1, 'limit': 20}
            headers = {}
            
            if api_key:
                headers['Api-Key'] = api_key
            
            response = requests.get(url, params=params, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get('results', []):
                    results.append(item)
            elif response.status_code == 429:
                # Rate limited, wait and retry
                continue
        except Exception as e:
            print(f"LeakIX search error: {e}")
    
    return results

def parse_leakix_result(item):
    """Parse LeakIX result to our format."""
    ip = item.get('ip', '')
    port = item.get('port', 0)
    service = item.get('service', '')
    
    # Calculate risk score based on exposure
    risk_score = 50
    
    if item.get('leak', {}):
        risk_score += 30
    if service in ['http', 'https']:
        risk_score += 20
    
    risk_score = min(risk_score, 100)
    
    return {
        'ip': ip,
        'port': port,
        'location': {
            'country_name': item.get('country', 'Unknown'),
            'city': item.get('city', 'Unknown')
        },
        'vulns': ['exposed_service'],
        'risk_score': risk_score,
        'source': 'leakix',
        'timestamp': datetime.now().isoformat()
    }

def mock_scan():
    """Generate mock data for demo."""
    return [
        {
            'ip': '45.33.32.156',
            'port': 3000,
            'location': {'country_name': 'United States', 'city': 'Dallas'},
            'vulns': ['exposed_api', 'no_auth'],
            'risk_score': 78,
            'source': 'leakix',
            'timestamp': datetime.now().isoformat()
        },
        {
            'ip': '138.68.10.122',
            'port': 8080,
            'location': {'country_name': 'United Kingdom', 'city': 'London'},
            'vulns': ['default_config'],
            'risk_score': 55,
            'source': 'leakix',
            'timestamp': datetime.now().isoformat()
        }
    ]

def run_scan():
    """Main scan function."""
    api_key = get_api_credentials()
    
    if api_key:
        print("🔍 Scanning with LeakIX API...")
        all_results = search_leakix('Clawdbot', api_key)
    else:
        print("⚠️  No LeakIX API key. Using mock data.")
        print("   Set LEAKIX_API_KEY env var for real scans.")
        all_results = mock_scan()
    
    # Parse results
    results = []
    for item in all_results:
        if isinstance(item, dict):
            parsed = parse_leakix_result(item)
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
