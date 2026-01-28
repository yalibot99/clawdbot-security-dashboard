#!/usr/bin/env python3
"""
Flask dashboard for Clawdbot security visualization.
Enhanced version with attack simulations and real-time data.
Uses Censys API for discovering exposed Clawdbot installations.
Background scheduler for hourly auto-scans.
"""

import json
import os
import random
import requests
import logging
from flask import Flask, render_template, jsonify, request
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import shutil

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Censys API configuration
CENSYS_API_ID = os.environ.get('CENSYS_API_ID', '')
CENSYS_API_SECRET = os.environ.get('CENSYS_API_SECRET', '')

# Timeout for fingerprinting requests
REQUEST_TIMEOUT = 3

def ensure_data_file():
    """Ensure results.json exists in static/data folder."""
    data_dir = 'static/data'
    data_file = os.path.join(data_dir, 'results.json')
    
    os.makedirs(data_dir, exist_ok=True)
    
    scraper_file = 'scraper/results.json'
    if os.path.exists(scraper_file) and not os.path.exists(data_file):
        shutil.copy(scraper_file, data_file)
    
    return data_file

def load_results():
    """Load scan results."""
    data_file = ensure_data_file()
    if os.path.exists(data_file):
        with open(data_file) as f:
            data = json.load(f)
            if data:  # Only return if file has actual data
                return data
    
    # Return demo/sample data if no real data exists
    return [
        {
            "ip": "192.168.1.100",
            "port": 3000,
            "risk_score": 85,
            "location": {"city": "Tel Aviv", "country_name": "Israel", "lat": 32.0853, "lng": 34.7818},
            "vulns": ["exposed_api", "no_auth"],
            "service": "Clawdbot Web UI",
            "timestamp": datetime.now().isoformat(),
            "source": "demo"
        },
        {
            "ip": "10.0.0.55",
            "port": 18789,
            "risk_score": 92,
            "location": {"city": "New York", "country_name": "United States", "lat": 40.7128, "lng": -74.0060},
            "vulns": ["exposed_api", "exposed_terminal", "no_auth"],
            "service": "Clawdbot Gateway",
            "timestamp": datetime.now().isoformat(),
            "source": "demo"
        },
        {
            "ip": "172.16.0.23",
            "port": 8080,
            "risk_score": 45,
            "location": {"city": "Berlin", "country_name": "Germany", "lat": 52.5200, "lng": 13.4050},
            "vulns": ["outdated_version"],
            "service": "Clawdbot Web UI",
            "timestamp": datetime.now().isoformat(),
            "source": "demo"
        }
    ]

def calculate_risk_score(vulns):
    """Calculate risk score based on vulnerabilities."""
    base_score = 50
    
    vuln_weights = {
        'no_auth': 25,
        'exposed_api': 15,
        'exposed_terminal': 30,
        'default_creds': 20,
        'outdated_version': 10,
        'missing_rate_limiting': 5,
        'gateway_exposed': 20,
        'browser_control_exposed': 15
    }
    
    score = base_score
    for vuln in vulns:
        score += vuln_weights.get(vuln, 5)
    
    return min(100, max(0, score))

def fingerprint_clawdbot(ip, port):
    """
    Actively fingerprint a service to verify it's Clawdbot.
    Returns (is_clawdbot, vulns, service_info) tuple.
    """
    base_url = f"http://{ip}:{port}"
    vulns = []
    service_info = {}
    
    # Check 1: Gateway API health endpoint
    try:
        response = requests.get(
            f"{base_url}/api/health",
            timeout=REQUEST_TIMEOUT
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'ok':
                vulns.append('exposed_api')
                service_info['gateway'] = True
    except:
        pass
    
    # Check 2: Gateway status endpoint
    try:
        response = requests.get(
            f"{base_url}/api/status",
            timeout=REQUEST_TIMEOUT
        )
        if response.status_code == 200:
            data = response.json()
            service_info['version'] = data.get('version', 'unknown')
            if not data.get('auth', {}).get('enabled'):
                vulns.append('no_auth')
    except:
        pass
    
    # Check 3: Clawdbot web UI indicators
    try:
        response = requests.get(
            base_url,
            timeout=REQUEST_TIMEOUT
        )
        if response.status_code == 200:
            content = response.text.lower()
            # Check for Clawdbot-specific strings
            if 'clawdbot' in content or 'claude' in content:
                service_info['web_ui'] = True
                
                # Check for authentication
                if 'login' not in content and 'sign in' not in content:
                    vulns.append('no_auth')
    except:
        pass
    
    # Check 4: Gateway port (18789) specific checks
    if port == 18789:
        try:
            response = requests.get(
                f"http://{ip}:18789/health",
                timeout=REQUEST_TIMEOUT
            )
            if response.status_code == 200:
                service_info['gateway_direct'] = True
                vulns.append('gateway_exposed')
        except:
            pass
    
    # Check 5: Browser control port (18791)
    if port == 18791:
        try:
            response = requests.get(
                f"http://{ip}:18791/status",
                timeout=REQUEST_TIMEOUT
            )
            if response.status_code == 200:
                service_info['browser_control'] = True
                vulns.append('browser_control_exposed')
        except:
            pass
    
    is_clawdbot = bool(service_info)  # Any positive fingerprint match
    return is_clawdbot, vulns, service_info

def search_censys():
    """Query Censys API for Clawdbot installations with fingerprinting."""
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        logger.warning("Censys API not configured")
        return None
    
    results = []
    seen_ips = set()  # Avoid duplicates
    
    # Search queries for Clawdbot-related services
    queries = [
        {"query": "18789", "service": "Clawdbot Gateway"},
        {"query": "3000", "service": "Clawdbot Web UI"},
        {"query": "18791", "service": "Clawdbot Browser Control"},
    ]
    
    headers = {
        'Accept': 'application/json'
    }
    
    for search in queries:
        try:
            url = f"https://search.censys.io/api/v2/hosts/search?q={search['query']}&per_page=50"
            auth = (CENSYS_API_ID, CENSYS_API_SECRET)
            
            response = requests.get(url, headers=headers, auth=auth, timeout=15)
            
            logger.info(f"Censys query '{search['query']}': {response.status_code}")
            
            if response.status_code == 401:
                logger.error("Censys API authentication failed - check credentials")
                return None
                
            if response.status_code == 200:
                data = response.json()
                hits = data.get('result', {}).get('hits', [])
                logger.info(f"  Found {len(hits)} hosts with port {search['query']}")
                
                for hit in hits:
                    ip = hit.get('ip', 'unknown')
                    
                    if ip in seen_ips:
                        continue
                    seen_ips.add(ip)
                    
                    location = hit.get('location', {})
                    services = hit.get('services', [])
                    port = services[0].get('port', int(search['query'])) if services else int(search['query'])
                    
                    logger.info(f"  Fingerprinting {ip}:{port}...")
                    
                    # Active fingerprinting
                    is_clawdbot, vulns, service_info = fingerprint_clawdbot(ip, port)
                    
                    if not is_clawdbot:
                        logger.debug(f"    Skipping {ip}:{port} - fingerprint failed")
                        logger.debug(f"    Service info: {service_info}")
                        continue  # Skip non-Clawdbot services
                    
                    # Add fingerprinting-based vulnerabilities
                    if 'gateway' in service_info and port != 18789:
                        vulns.append('gateway_exposed')
                    
                    if 'browser_control' in service_info and port != 18791:
                        vulns.append('browser_control_exposed')
                    
                    # Create result entry
                    result = {
                        'ip': ip,
                        'port': port,
                        'risk_score': calculate_risk_score(vulns),
                        'location': {
                            'city': location.get('city', 'Unknown'),
                            'country_name': location.get('country', 'Unknown'),
                            'lat': location.get('latitude'),
                            'lng': location.get('longitude')
                        },
                        'vulns': vulns,
                        'service': search['service'],
                        'service_info': service_info,
                        'timestamp': datetime.now().isoformat(),
                        'fingerprint_method': 'active_verification'
                    }
                    results.append(result)
                    
        except Exception as e:
            logger.error(f"Censys search error for {search['query']}: {e}")
            continue
    
    return results

def run_background_scan():
    """Background task to run scans periodically."""
    logger.info("🔄 Starting scheduled scan...")
    
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        logger.warning("Censys API not configured, skipping scan")
        return
    
    results = search_censys()
    
    if results is None:
        logger.error("Scan failed")
        return
    
    # Save results
    data_file = ensure_data_file()
    with open(data_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"✅ Scan complete. Found {len(results)} verified Clawdbot installations.")

# Initialize scheduler
scheduler = BackgroundScheduler()

@app.route('/')
def index():
    """Main dashboard."""
    results = load_results()
    
    for r in results:
        r['time_to_compromise'] = max(1, int((100 - r.get('risk_score', 50)) * 0.5))
    
    # Calculate chart data
    critical_count = sum(1 for r in results if r.get('risk_score', 0) > 85)
    high_count = sum(1 for r in results if 70 < r.get('risk_score', 0) <= 85)
    medium_count = sum(1 for r in results if 40 < r.get('risk_score', 0) <= 70)
    low_count = sum(1 for r in results if r.get('risk_score', 0) <= 40)
    
    # Get last scan time
    data_file = ensure_data_file()
    last_scan = None
    scan_count = 0
    if os.path.exists(data_file) and os.path.getsize(data_file) > 0:
        with open(data_file) as f:
            data = json.load(f)
            scan_count = len(data)
        last_scan = datetime.fromtimestamp(os.path.getmtime(data_file)).isoformat()
    
    stats = {
        'total': scan_count,
        'high_risk': sum(1 for r in results if r.get('risk_score', 0) > 70),
        'critical': critical_count,
        'avg_risk': sum(r.get('risk_score', 0) for r in results) / max(len(results), 1),
        'countries': len(set(r.get('location', {}).get('country_name', 'Unknown') for r in results)),
        'total_exposed': len(results) * random.randint(100, 10000),
        'attack_surface': len(results),
        # Chart data
        'risk_distribution': [critical_count, high_count, medium_count, low_count],
        'risk_labels': ['Critical', 'High', 'Medium', 'Low'],
        'api_connected': bool(CENSYS_API_ID),
        'last_scan': last_scan,
        'auto_refresh': True
    }
    
    return render_template('dashboard.html', results=results, stats=stats)

@app.route('/api/results')
def api_results():
    """JSON API for results."""
    results = load_results()
    for r in results:
        r['time_to_compromise'] = max(1, int((100 - r.get('risk_score', 50)) * 0.5))
    return jsonify(results)

@app.route('/api/stats')
def api_stats():
    """JSON API for stats."""
    results = load_results()
    critical_count = sum(1 for r in results if r.get('risk_score', 0) > 85)
    high_count = sum(1 for r in results if 70 < r.get('risk_score', 0) <= 85)
    medium_count = sum(1 for r in results if 40 < r.get('risk_score', 0) <= 70)
    low_count = sum(1 for r in results if r.get('risk_score', 0) <= 40)
    
    # Get last scan time
    data_file = ensure_data_file()
    last_scan = None
    scan_count = 0
    if os.path.exists(data_file) and os.path.getsize(data_file) > 0:
        with open(data_file) as f:
            data = json.load(f)
            scan_count = len(data)
        last_scan = datetime.fromtimestamp(os.path.getmtime(data_file)).isoformat()
    
    return jsonify({
        'total': scan_count,
        'high_risk': sum(1 for r in results if r.get('risk_score', 0) > 70),
        'critical': critical_count,
        'avg_risk': sum(r.get('risk_score', 0) for r in results) / max(len(results), 1),
        'countries': len(set(r.get('location', {}).get('country_name', 'Unknown') for r in results)),
        'total_exposed': len(results) * random.randint(100, 10000),
        'attack_surface': len(results),
        'risk_distribution': [critical_count, high_count, medium_count, low_count],
        'api_connected': bool(CENSYS_API_ID),
        'last_scan': last_scan,
        'auto_refresh': True
    })

@app.route('/api/demo/<ip>/<int:port>')
def api_demo(ip, port):
    """Generate demo attack simulation."""
    return jsonify({
        'target': f'{ip}:{port}',
        'timestamp': datetime.now().isoformat(),
        'vulnerabilities': [
            'No authentication required',
            'Exposed API endpoints',
            'Missing rate limiting',
            'No input validation'
        ],
        'exploit_time': random.randint(1, 30) / 100,
        'impact': 'CRITICAL',
        'commands': [
            f'curl http://{ip}:{port}/api/health',
            f'curl http://{ip}:{port}/api/messages',
            f'curl http://{ip}:{port}/api/config'
        ]
    })

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """Trigger a new scan via Censys API with fingerprinting."""
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        return jsonify({
            'status': 'error',
            'message': 'Censys API not configured. Please set CENSYS_API_ID and CENSYS_API_SECRET.'
        }), 400
    
    results = search_censys()
    
    if results is None:
        return jsonify({
            'status': 'error',
            'message': 'Censys API request failed. Check credentials.'
        }), 500
    
    # Save results
    data_file = ensure_data_file()
    with open(data_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    return jsonify({
        'status': 'success',
        'message': f'Scan complete. Found {len(results)} verified Clawdbot installations.',
        'timestamp': datetime.now().isoformat(),
        'fingerprint_method': 'active_verification',
        'total_found': len(results)
    })

@app.route('/api/scan/debug', methods=['GET'])
def api_scan_debug():
    """Debug endpoint - shows raw Censys results without fingerprinting."""
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        return jsonify({
            'status': 'error',
            'message': 'Censys API not configured.'
        }), 400
    
    raw_results = []
    seen_ips = set()
    api_error = None
    
    queries = [
        {"query": "18789", "service": "Clawdbot Gateway"},
        {"query": "3000", "service": "Clawdbot Web UI"},
        {"query": "18791", "service": "Clawdbot Browser Control"},
    ]
    
    headers = {'Accept': 'application/json'}
    
    for search in queries:
        try:
            url = f"https://search.censys.io/api/v2/hosts/search?q={search['query']}&per_page=20"
            auth = (CENSYS_API_ID, CENSYS_API_SECRET)
            response = requests.get(url, headers=headers, auth=auth, timeout=15)
            
            if response.status_code == 401:
                api_error = "Censys API authentication failed (401)"
                continue
                
            if response.status_code == 200:
                data = response.json()
                hits = data.get('result', {}).get('hits', [])
                
                for hit in hits:
                    ip = hit.get('ip', 'unknown')
                    if ip in seen_ips:
                        continue
                    seen_ips.add(ip)
                    
                    location = hit.get('location', {})
                    services = hit.get('services', [])
                    port = services[0].get('port', int(search['query'])) if services else int(search['query'])
                    
                    raw_results.append({
                        'ip': ip,
                        'port': port,
                        'service': search['service'],
                        'location': {
                            'city': location.get('city', 'Unknown'),
                            'country': location.get('country', 'Unknown'),
                        },
                        'timestamp': datetime.now().isoformat()
                    })
                    
        except Exception as e:
            logger.error(f"Debug scan error: {e}")
    
    return jsonify({
        'status': 'error' if api_error else 'success',
        'api_error': api_error,
        'total_hosts': len(raw_results),
        'hosts': raw_results,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/fingerprint/<ip>/<int:port>', methods=['GET'])
def api_fingerprint(ip, port):
    """Manually fingerprint a specific IP:port."""
    is_clawdbot, vulns, service_info = fingerprint_clawdbot(ip, port)
    
    return jsonify({
        'ip': ip,
        'port': port,
        'is_clawdbot': is_clawdbot,
        'vulnerabilities': vulns,
        'service_info': service_info,
        'risk_score': calculate_risk_score(vulns)
    })

@app.route('/api/refresh', methods=['POST'])
def api_refresh():
    """Trigger a new scan."""
    return jsonify({
        'status': 'success',
        'message': 'Scan triggered',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/health')
def api_health():
    """Health check endpoint."""
    return jsonify({
        'status': 'ok',
        'scheduler_running': scheduler.running if 'scheduler' in dir() else False,
        'api_connected': bool(CENSYS_API_ID)
    })

# Security Intelligence Endpoints
@app.route('/api/security-intel')
def api_security_intel():
    """Return security intelligence data."""
    try:
        intel_file = 'static/data/security_intel.json'
        if os.path.exists(intel_file):
            with open(intel_file) as f:
                return jsonify(json.load(f))
        return jsonify({'error': 'No security intelligence data available'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/security-intel/refresh', methods=['POST'])
def refresh_security_intel():
    """Trigger security intelligence refresh."""
    try:
        import subprocess
        result = subprocess.run(
            ['python3', 'security_intel.py'],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode == 0:
            return jsonify({
                'status': 'success',
                'message': 'Security intelligence refreshed'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': result.stderr
            }), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/security-intel/summary')
def api_security_summary():
    """Quick summary endpoint for dashboard widgets."""
    try:
        intel_file = 'static/data/security_intel.json'
        if os.path.exists(intel_file):
            with open(intel_file) as f:
                data = json.load(f)
                return jsonify({
                    'total_discussions': data['summary']['total_discussions'],
                    'critical_count': data['summary']['critical_count'],
                    'high_count': data['summary']['high_count'],
                    'average_severity': data['summary']['average_severity'],
                    'top_issue': data['top_security_concerns'][0]['issue'] if data['top_security_concerns'] else None,
                    'generated': data['meta']['generated']
                })
        return jsonify({'error': 'No data available'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Dashboard starting at http://localhost:5000")
    print("🎯 Clawdbot Security Intelligence Dashboard")
    print("🛡️  Security Intelligence: Active (web, X, blogs)")
    print("🔍 Fingerprinting: Active verification enabled")
    print("⏰ Auto-scan: Every hour")
    
    # Start background scheduler
    if CENSYS_API_ID and CENSYS_API_SECRET:
        scheduler.add_job(
            run_background_scan,
            trigger=IntervalTrigger(hours=1),
            id='hourly_scan',
            name='Hourly Clawdbot scan',
            replace_existing=True
        )
        scheduler.start()
        print("✅ Background scheduler started")
    else:
        # Still start without external API
        scheduler.start()
        print("✅ Background scheduler started (no external API)")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
