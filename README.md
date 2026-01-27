# Clawdbot Security Dashboard

Security awareness tool that discovers and visualizes accessible Clawdbot installations.

## 🚨 Warning

This dashboard demonstrates the **critical security risks** of exposed Clawdbot installations. Each exposed instance can be fully compromised in minutes.

## 🎯 Features

### Attack Simulation Demo
Click "🎯 Demo Exploit" on any card to see a simulated attack chain.

### Interactive Dashboard
- **🗺️ World Map** - Geographic distribution of exposed installations
- **📊 Risk Charts** - Visual breakdown of risk levels
- **📈 Historical Trends** - Track discovery over time
- **🔍 Search & Filter** - Find by IP, country, risk score
- **🌍 Country Filter** - Focus on specific regions

### Security Metrics
- **⏱️ Time to Compromise** - Estimated breach time
- **💀 Attack Vectors** - What attackers can do
- **📄 Export Reports** - JSON reports for security audits

### Multiple Data Sources
- **Shodan** (paid)
- **Censys** (free tier)
- **BinaryEdge** (free tier)
- **LeakIX** (free)

## 🚀 Quick Start

### Option 1: Docker (Recommended)
```bash
# Clone and run
git clone https://github.com/yalibot99/clawdbot-security-dashboard.git
cd clawdbot-security-dashboard

# With environment variables
export SHODAN_API_KEY=your_key
export CENSYS_API_ID=your_id
export CENSYS_API_SECRET=your_secret

# Run with Docker
docker-compose up -d

# Or just the dashboard
docker build -t clawdbot-dashboard .
docker run -p 5000:5000 clawdbot-dashboard
```

### Option 2: Python
```bash
# Install dependencies
pip install -r requirements.txt

# Set API keys (optional)
export SHODAN_API_KEY=your_key
export CENSYS_API_ID=your_id
export CENSYS_API_SECRET=your_secret

# Run a scraper
python scraper/shodan_scraper.py
# or
python scraper/censys_scraper.py
# or
python scraper/binaryedge_scraper.py

# Start the dashboard
python app.py
```

## 📁 Project Structure

```
clawdbot-security-dashboard/
├── app.py                    # Flask dashboard server
├── Dockerfile                # Docker container
├── docker-compose.yml        # Docker orchestration
├── requirements.txt          # Python dependencies
├── .github/
│   └── workflows/
│       └── ci-cd.yml         # GitHub Actions CI/CD
├── scraper/
│   ├── shodan_scraper.py     # Shodan API
│   ├── censys_scraper.py     # Censys API (free tier)
│   ├── binaryedge_scraper.py # BinaryEdge API (free tier)
│   ├── leakix_scraper.py     # LeakIX (free)
│   └── results.json          # Scan results
├── templates/
│   └── dashboard.html        # Enhanced UI
├── static/
│   └── data/
│       └── results.json      # Dashboard data
├── tests/
│   └── test_dashboard.py     # Unit tests
└── README.md
```

## 🔧 Environment Variables

| Variable | Source | Purpose |
|----------|--------|---------|
| `SHODAN_API_KEY` | Shodan | Real Shodan scans |
| `CENSYS_API_ID` | Censys | Censys API (free tier) |
| `CENSYS_API_SECRET` | Censys | Censys API secret |
| `BINARYEDGE_API_KEY` | BinaryEdge | BinaryEdge API (free tier) |
| `LEAKIX_API_KEY` | LeakIX | LeakIX API (optional) |

## 📡 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main dashboard UI |
| `/api/results` | GET | JSON list of findings |
| `/api/stats` | GET | Aggregate statistics |
| `/api/demo/<ip>/<port>` | GET | Attack simulation data |
| `/api/refresh` | POST | Trigger new scan |
| `/api/export` | GET | Export full report |

## 🧪 Testing

```bash
# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html
```

## 🚢 Deployment

### Render (Free Tier)
1. Connect GitHub repo: `yalibot99/clawdbot-security-dashboard`
2. Build Command: `pip install -r requirements.txt`
3. Start Command: `python app.py`

### Docker
```bash
docker build -t clawdbot-dashboard .
docker run -p 5000:5000 clawdbot-dashboard
```

### Docker Compose
```bash
docker-compose up -d
```

## 📊 Dashboard Features

- **Real-time metrics** with auto-refresh
- **Interactive world map** with Leaflet.js
- **Risk distribution charts** with Chart.js
- **Historical trend analysis**
- **Search and filter** capabilities
- **PDF/JSON export** for reports
- **Dark mode** support
- **Mobile responsive** design

## ⚠️ Educational Use Only

This tool is for:
- Security research and awareness
- Penetration testing education
- Vulnerability disclosure preparation

**Do NOT use for malicious purposes.**

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for your changes
4. Ensure all tests pass
5. Submit a pull request

## 📝 License

MIT License - See LICENSE file for details.

---

Built for the Israeli cybersecurity community 🦾
