#!/usr/bin/env python3
"""
Flask dashboard for Clawdbot security visualization.
"""

import json
import os
from flask import Flask, render_template, jsonify
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
    stats = {
        'total': len(results),
        'high_risk': sum(1 for r in results if r.get('risk_score', 0) > 70),
        'avg_risk': sum(r.get('risk_score', 0) for r in results) / max(len(results), 1),
        'countries': set(r.get('location', {}).get('country_name', 'Unknown') for r in results)
    }
    return render_template('dashboard.html', results=results, stats=stats)

@app.route('/api/results')
def api_results():
    """JSON API for results."""
    return jsonify(load_results())

@app.route('/api/stats')
def api_stats():
    """JSON API for stats."""
    results = load_results()
    return jsonify({
        'total': len(results),
        'high_risk': sum(1 for r in results if r.get('risk_score', 0) > 70),
        'avg_risk': sum(r.get('risk_score', 0) for r in results) / max(len(results), 1)
    })

if __name__ == '__main__':
    print("🚀 Dashboard starting at http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
