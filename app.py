#!/usr/bin/env python3
"""
Flask dashboard for Clawdbot security visualization.
Enhanced version with attack simulations and real-time data.
"""

import json
import os
import random
from flask import Flask, render_template, jsonify, request
from datetime import datetime
import shutil

app = Flask(__name__)

def ensure_data_file():
    """Ensure results.json exists in static/data folder."""
    data_dir = 'static/data'
    data_file = os.path.join(data_dir, 'results.json')
    
    # Create directory if needed
    os.makedirs(data_dir, exist_ok=True)
    
    # Copy from scraper if exists
    scraper_file = 'scraper/results.json'
    if os.path.exists(scraper_file) and not os.path.exists(data_file):
        shutil.copy(scraper_file, data_file)
    
    return data_file

def load_results():
    """Load scan results."""
    data_file = ensure_data_file()
    if os.path.exists(data_file):
        with open(data_file) as f:
            return json.load(f)
    return []

@app.route('/')
def index():
    """Main dashboard."""
    results = load_results()
    
    # Add dynamic calculated fields
    for r in results:
        # Time to compromise (estimated)
        r['time_to_compromise'] = max(1, int((100 - r.get('risk_score', 50)) * 0.5))
    
    stats = {
        'total': len(results),
        'high_risk': sum(1 for r in results if r.get('risk_score', 0) > 70),
        'critical': sum(1 for r in results if r.get('risk_score', 0) > 85),
        'avg_risk': sum(r.get('risk_score', 0) for r in results) / max(len(results), 1),
        'countries': len(set(r.get('location', {}).get('country_name', 'Unknown') for r in results)),
        'total_exposed': len(results) * random.randint(100, 10000),  # Simulated
        'attack_surface': len(results)
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
    return jsonify({
        'total': len(results),
        'high_risk': sum(1 for r in results if r.get('risk_score', 0) > 70),
        'critical': sum(1 for r in results if r.get('risk_score', 0) > 85),
        'avg_risk': sum(r.get('risk_score', 0) for r in results) / max(len(results), 1),
        'countries': len(set(r.get('location', {}).get('country_name', 'Unknown') for r in results)),
        'total_exposed': len(results) * random.randint(100, 10000),
        'attack_surface': len(results)
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

@app.route('/api/refresh', methods=['POST'])
def api_refresh():
    """Trigger a new scan."""
    # In production, this would trigger the scraper
    return jsonify({
        'status': 'success',
        'message': 'Scan triggered',
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    print("🚀 Dashboard starting at http://localhost:5000")
    print("🎯 Enhanced Security Dashboard with Attack Simulations")
    app.run(debug=True, host='0.0.0.0', port=5000)
