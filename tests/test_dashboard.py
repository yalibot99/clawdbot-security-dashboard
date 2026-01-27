import pytest
import json
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture
def sample_results():
    return [
        {
            'ip': '192.168.1.100',
            'port': 3000,
            'location': {'country_name': 'Israel', 'city': 'Tel Aviv'},
            'vulns': ['exposed_api', 'no_auth'],
            'risk_score': 85
        },
        {
            'ip': '10.0.0.55',
            'port': 3000,
            'location': {'country_name': 'United States', 'city': 'New York'},
            'vulns': ['default_creds'],
            'risk_score': 92
        }
    ]

def test_index_route(client):
    """Test that the index route loads."""
    response = client.get('/')
    assert response.status_code == 200

def test_api_results(client, sample_results):
    """Test the API results endpoint."""
    # Create a temporary results file
    with open('scraper/results.json', 'w') as f:
        json.dump(sample_results, f)
    
    response = client.get('/api/results')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data) == 2
    
    # Cleanup
    os.remove('scraper/results.json')

def test_api_stats(client, sample_results):
    """Test the API stats endpoint."""
    with open('scraper/results.json', 'w') as f:
        json.dump(sample_results, f)
    
    response = client.get('/api/stats')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'total' in data
    assert 'high_risk' in data
    assert data['total'] == 2
    assert data['high_risk'] == 2  # Both have risk > 70
    
    os.remove('scraper/results.json')

def test_api_demo(client):
    """Test the demo attack simulation endpoint."""
    response = client.get('/api/demo/192.168.1.100/3000')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['target'] == '192.168.1.100:3000'
    assert 'vulnerabilities' in data
    assert 'commands' in data

def test_api_refresh(client):
    """Test the refresh endpoint."""
    response = client.post('/api/refresh')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['status'] == 'success'

def test_risk_calculation(sample_results):
    """Test that risk scores are calculated correctly."""
    for result in sample_results:
        assert result['risk_score'] >= 0
        assert result['risk_score'] <= 100

def test_location_data(sample_results):
    """Test that location data is properly formatted."""
    for result in sample_results:
        assert 'location' in result
        assert 'country_name' in result['location']
        assert 'city' in result['location']

def test_vulnerabilities_list(sample_results):
    """Test that vulnerabilities are properly formatted."""
    for result in sample_results:
        assert 'vulns' in result
        assert isinstance(result['vulns'], list)
        for vuln in result['vulns']:
            assert isinstance(vuln, str)
