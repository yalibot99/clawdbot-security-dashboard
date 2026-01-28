# Clawdbot Security Intelligence Dashboard 🛡️

Real-time security intelligence monitoring for Clawdbot and AI agent security discussions.

## 🎯 Features

### Security Intelligence Monitor
- **📊 Severity Ratings** - Critical, High, Medium, Low with automated scoring
- **📰 Multi-Source Aggregation** - X/Twitter, Hacker News, Reddit, security blogs
- **🚨 Top Security Concerns** - Ranked issues with mitigations
- **💡 Actionable Recommendations** - Practical security advice for each issue

### Dashboard Widgets
- **Total Discussions** - 24h volume of security mentions
- **Critical Count** - Number of critical severity issues
- **High Severity Count** - High-priority security concerns
- **Average Severity Score** - Overall security posture metric (0-100)

### Interactive Charts
- **Severity Distribution** - Doughnut chart of issue severity
- **Source Breakdown** - Bar chart showing discussion sources
- **Trend Analysis** - Track security discussions over time

### Data Sources
- **X/Twitter** - Via web search for real-time discussions
- **Hacker News** - Algolia API search
- **Reddit** - r/netsec, r/cybersecurity via Pushshift
- **Security Blogs** - The Register, Bitdefender, ForkLog, Cointelegraph, The Hacker News

## 🚀 Quick Start

```bash
# Clone and run
git clone https://github.com/yalibot99/clawdbot-security-dashboard.git
cd clawdbot-security-dashboard

# Install dependencies
pip install flask apscheduler requests feedparser

# Run security intelligence gathering
python security_intel.py

# Start the dashboard
python app.py

# Open in browser
# http://localhost:5000
```

## 📁 Project Structure

```
clawdbot-security-dashboard/
├── app.py                    # Flask dashboard server
├── security_intel.py         # Security intelligence gathering
├── templates/
│   └── dashboard.html        # Enhanced dashboard UI
├── static/
│   └── data/
│       └── security_intel.json  # Intelligence data
├── requirements.txt          # Python dependencies
└── README.md
```

## 📡 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main dashboard UI |
| `/api/security-intel` | GET | Full intelligence data |
| `/api/security-intel/summary` | GET | Quick summary for widgets |
| `/api/security-intel/refresh` | POST | Refresh intelligence data |

## 🔧 Severity Scoring

Issues are scored based on keyword presence:

| Severity | Score | Keywords |
|----------|-------|----------|
| Critical | 100 | RCE, root, unauthenticated, cryptocurrency theft, credential theft |
| High | 75 | Exposed, vulnerability, exploit, API keys at risk, prompt injection |
| Medium | 50 | Concern, risk, recommend, best practice |
| Low | 25 | Tips, guide, setup, configuration |

## 🛡️ Tracked Security Issues

1. **Credential/API Key Exposure** - API keys, secrets in environment
2. **Authentication Bypass** - Unauthenticated access, reverse proxy issues
3. **Remote Code Execution (RCE)** - Command injection, shell access
4. **Signal Pairing Credentials** - Exposed pairing files in temp directories
5. **No Privilege Separation** - Running as root without isolation
6. **Prompt Injection** - Malicious input to LLM agents

## 📊 Example Output

```json
{
  "summary": {
    "total_discussions": 8,
    "critical_count": 4,
    "high_count": 0,
    "average_severity": 69.1
  },
  "top_security_concerns": [
    {
      "issue": "Credential/API Key Exposure",
      "count": 5,
      "mitigation": "Use environment variables, rotate keys regularly"
    }
  ]
}
```

## 🎓 Use Cases

- **Security Awareness** - Stay informed about Clawdbot security discussions
- **Threat Intelligence** - Monitor emerging security concerns
- **Vulnerability Tracking** - Track severity and frequency of issues
- **Mitigation Planning** - Get actionable security recommendations

## 🔄 Automated Updates

Run intelligence refresh manually or schedule with cron:

```bash
# Refresh every hour
0 * * * * cd /path/to/project && python security_intel.py
```

## 📝 License

MIT License - See LICENSE file for details.

---

Built for the Israeli cybersecurity community 🦾
# Trigger rebuild Wed Jan 28 00:22:48 UTC 2026
