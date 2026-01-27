# Clawdbot Security Dashboard

Security awareness tool that discovers and visualizes accessible Clawdbot installations.

## Quick Start

```bash
# Install dependencies
pip install shodan flask

# Set your Shodan API key
export SHODAN_API_KEY=your_key_here

# Run the scraper
python scraper/shodan_scraper.py

# Start the dashboard
python app.py
```

## Dashboard Features

- 🎯 Real-time discovery of exposed installations
- 💣 Ticking bomb indicators for high-risk systems
- 📊 Risk scoring and categorization
- 🔒 Security recommendations

## ⚠️ Educational Use Only

This tool is for security research and awareness. Always follow responsible disclosure practices.
