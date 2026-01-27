# Clawdbot Security Dashboard

Security awareness tool that discovers and visualizes accessible Clawdbot installations.

## Scraper Options

### 1. Shodan (Paid)
```bash
pip install shodan
export SHODAN_API_KEY=your_key_here
python scraper/shodan_scraper.py
```

### 2. Censys (Free Tier Available)
```bash
pip install censys requests
export CENSYS_API_ID=your_api_id
export CENSYS_API_SECRET=your_api_secret
python scraper/censys_scraper.py
```

### 3. Mock Mode (Demo)
No API needed — runs with sample data:
```bash
python scraper/shodan_scraper.py
# or
python scraper/censys_scraper.py
```

## Run Dashboard

```bash
python app.py
```

Dashboard will be at: http://localhost:5000

## Environment Variables

| Variable | Source | Purpose |
|----------|--------|---------|
| `SHODAN_API_KEY` | Shodan | Real Shodan scans |
| `CENSYS_API_ID` | Censys | Censys API (free tier) |
| `CENSYS_API_SECRET` | Censys | Censys API secret |

## Dashboard Features

- 🎯 Real-time discovery of exposed installations
- 💣 Ticking bomb indicators for high-risk systems
- 📊 Risk scoring and categorization
- 🔒 Security recommendations

## ⚠️ Educational Use Only

This tool is for security research and awareness. Always follow responsible disclosure practices.
