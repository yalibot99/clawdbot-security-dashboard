#!/usr/bin/env python3
"""
Flask dashboard for Clawdbot security visualization.
"""

import json
import os
from flask import Flask, render_template, jsonify
from datetime import datetime

app = Flask(__name__)

def load_results():
    """Load scan results."""
    results_file = 'scraper/results.json'
    if os.path.exists(results_file):
        with open(results_file) as f:
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
