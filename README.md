# Clawdbot Security Dashboard

Security awareness tool that discovers and visualizes accessible Clawdbot installations.

## 🚨 Warning

This dashboard demonstrates the **critical security risks** of exposed Clawdbot installations. Each exposed instance can be fully compromised in minutes.

## 🎯 Features

### Attack Simulation Demo
Click "🎯 Demo Exploit" on any card to see a simulated attack chain showing:
- API enumeration
- Message extraction
- Configuration theft
- Full system compromise

### Real-Time Metrics
- **Time to First Compromise** — Global countdown timer
- **Risk Scores** — Per-installation assessment
- **Attack Vectors** — What attackers can do
- **Impact Assessment** — CRITICAL/POSSIBLE/NONE

### Visual Indicators
- 💣 Ticking bomb animations for critical systems
- 🔴 Red pulse effect for critical vulnerabilities
- 📊 Risk meters with color coding
- ⏱️ Estimated time to compromise

## Quick Start

```bash
# Install dependencies
pip install shodan flask censys requests

# Set API keys (optional)
export SHODAN_API_KEY=your_key_here
export CENSYS_API_ID=your_id
export CENSYS_API_SECRET=your_secret

# Run the scraper
python scraper/shodan_scraper.py

# Start the dashboard
python app.py
```

## Dashboard Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | Main dashboard UI |
| `/api/results` | JSON list of all findings |
| `/api/stats` | Aggregate statistics |
| `/api/demo/<ip>/<port>` | Simulated attack data |
| `/api/refresh` | Trigger new scan (POST) |

## Project Structure

```
clawdbot-security-dashboard/
├── app.py              # Flask dashboard server
├── scraper/
│   ├── shodan_scraper.py   # Shodan API scraper
│   ├── censys_scraper.py   # Censys API scraper
│   └── results.json        # Scan results
├── templates/
│   └── dashboard.html      # Enhanced UI with attack simulation
├── static/data/
│   └── results.json        # Dashboard data
├── requirements.txt
└── README.md
```

## ⚠️ Educational Use Only

This tool is for:
- Security research and awareness
- Penetration testing education
- Vulnerability disclosure preparation

**Do NOT use for malicious purposes.**

## Deployment

Deploy to Render (free tier):

1. Connect GitHub repo: `yalibot99/clawdbot-security-dashboard`
2. Build Command: `pip install -r requirements.txt`
3. Start Command: `python app.py`

## Credits

Built for the Israeli cybersecurity community
