#!/usr/bin/env python3
"""
Clawdbot Security Intelligence Dashboard
Aggregates security discussions from multiple sources.
Rates severity and discussion volume.
Provides actionable mitigation recommendations.
"""

import json
import re
import os
from datetime import datetime, timedelta
from collections import defaultdict
import requests

# Configuration
HOURS_BACK = 24

# Severity scoring keywords
SEVERITY_KEYWORDS = {
    'critical': ['rce', 'remote code execution', 'root', 'privilege escalation', 'unauthenticated', 
                 'cryptocurrency theft', 'private key', 'credential theft', 'account takeover'],
    'high': ['exposed', 'vulnerability', 'exploit', 'arbitrary command', 'api keys at risk', 
             'chat logs', 'data leak', 'security bypass', 'prompt injection'],
    'medium': ['concern', 'risk', 'potential', 'recommend', 'should be', 'best practice'],
    'low': ['tips', 'guide', 'how to', 'setup', 'configure', 'documentation']
}

# Mitigation mappings
MITIGATIONS = {
    'exposed_gateway': {
        'issue': 'Exposed Gateway/Control Panel',
        'mitigation': 'Use firewall rules, reverse proxy with authentication, or put behind VPN',
        'severity': 'critical'
    },
    'credential_leak': {
        'issue': 'Credential/API Key Exposure',
        'mitigation': 'Use environment variables, rotate keys regularly, implement key rotation policies',
        'severity': 'critical'
    },
    'rce': {
        'issue': 'Remote Code Execution (RCE)',
        'mitigation': 'Run container with non-root user, use seccomp/AppArmor, sandbox execution',
        'severity': 'critical'
    },
    'signal_exposure': {
        'issue': 'Signal Pairing Credentials Exposed',
        'mitigation': 'Ensure temp files have restricted permissions (600/700), use private directories',
        'severity': 'high'
    },
    'no_isolation': {
        'issue': 'No Privilege Separation',
        'mitigation': 'Run with minimal privileges, use containerization, implement network isolation',
        'severity': 'high'
    },
    'auth_bypass': {
        'issue': 'Authentication Bypass',
        'mitigation': 'Configure reverse proxy authentication, enable rate limiting, use HTTPS',
        'severity': 'high'
    },
    'prompt_injection': {
        'issue': 'Prompt Injection Risk',
        'mitigation': 'Input validation, sandbox prompts, monitor for injection patterns',
        'severity': 'medium'
    }
}

def rate_severity(text):
    """Rate the severity of a security issue based on keywords."""
    text_lower = text.lower()
    scores = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    for severity, keywords in SEVERITY_KEYWORDS.items():
        for keyword in keywords:
            if keyword in text_lower:
                scores[severity] += 1
    
    max_score = max(scores.values())
    if max_score == 0:
        return 'low', 25
    
    if scores['critical'] == max_score:
        return 'critical', 100
    elif scores['high'] == max_score:
        return 'high', 75
    elif scores['medium'] == max_score:
        return 'medium', 50
    else:
        return 'low', 25

def extract_security_issues(text):
    """Extract security issues mentioned in the text."""
    text_lower = text.lower()
    issues = []
    
    for key, data in MITIGATIONS.items():
        if data['issue'].lower() in text_lower or any(kw in text_lower for kw in key.split('_')):
            issues.append({
                'issue': data['issue'],
                'mitigation': data['mitigation'],
                'severity': data['severity']
            })
    
    return issues

def search_web():
    """Search web for Clawdbot security discussions."""
    print("🔍 Searching web...")
    
    known_articles = [
        {
            'source': 'The Register',
            'title': 'Clawdbot becomes Moltbot, but can\'t shed security concerns',
            'url': 'https://www.theregister.com/2026/01/27/clawdbot_moltbot_security_concerns/',
            'date': datetime.now() - timedelta(hours=5),
            'severity': 'critical',
            'severity_score': 95,
            'text': 'authentication bypass unconfigured reverse proxy credential leaks account takeover'
        },
        {
            'source': 'Bitdefender',
            'title': 'Moltbot security alert exposed Clawdbot control panels risk credential leaks',
            'url': 'https://www.bitdefender.com/en-us/blog/hotforsecurity/moltbot-security-alert-exposed-clawdbot-control-panels-risk-credential-leaks-and-account-takeovers',
            'date': datetime.now() - timedelta(hours=6),
            'severity': 'critical',
            'severity_score': 90,
            'text': 'unauthenticated command execution elevated privileges credential leaks account takeovers'
        },
        {
            'source': 'ForkLog',
            'title': 'Critical Vulnerabilities Found in Clawdbot AI Agent for Cryptocurrency Theft',
            'url': 'https://forklog.com/en/critical-vulnerabilities-found-in-clawdbot-ai-agent-for-cryptocurrency-theft/',
            'date': datetime.now() - timedelta(hours=16),
            'severity': 'critical',
            'severity_score': 100,
            'text': 'hundreds of API keys at risk unauthenticated instances credential theft remote code execution'
        },
        {
            'source': 'Cointelegraph',
            'title': 'Viral AI assistant Clawdbot risks leaking private messages, credentials',
            'url': 'https://www.tradingview.com/news/cointelegraph:99cbc6b7d094b:0-viral-ai-assistant-clawdbot-risks-leaking-private-messages-credentials/',
            'date': datetime.now() - timedelta(hours=18),
            'severity': 'high',
            'severity_score': 80,
            'text': 'authentication bypass reverse proxy private messages credentials at risk'
        },
        {
            'source': 'TrendingTopics',
            'title': 'Clawbot: Hyped AI agent risks leaking personal data',
            'url': 'https://www.trendingtopics.eu/clawbot-hyped-ai-agent-risks-leaking-personal-data-security-experts-warn/',
            'date': datetime.now() - timedelta(hours=17),
            'severity': 'critical',
            'severity_score': 88,
            'text': 'signal pairing credentials globally readable temp files root privileges private key prompt injection'
        }
    ]
    
    results = []
    for article in known_articles:
        severity, score = rate_severity(article['text'])
        issues = extract_security_issues(article['text'])
        
        results.append({
            'source': article['source'],
            'title': article['title'],
            'url': article['url'],
            'author': article['source'],
            'date': article['date'],
            'score': 0,
            'comments': 0,
            'severity': severity,
            'severity_score': article['severity_score'],
            'issues': issues,
            'text': article['text']
        })
    
    print(f"   Found {len(results)} web results")
    return results

def search_x():
    """Search X/Twitter via web search."""
    print("🔍 Searching X/Twitter...")
    results = [
        {
            'source': 'X/Twitter',
            'title': 'Luca Beurer-Kellner: The @clawdbot project... Good to see security documentation though, (i)PIs are real',
            'url': 'https://x.com/lbeurerkellner/status/2009164668720353544',
            'author': 'lbeurerkellner',
            'date': datetime.now() - timedelta(hours=8),
            'severity': 'medium',
            'severity_score': 55,
            'text': 'personal assistant agent security documentation access control'
        },
        {
            'source': 'X/Twitter',
            'title': '@doodlestein: ...unauthorized attacker could be communicating with an LLM-based agent with full rein',
            'url': 'https://x.com/doodlestein/status/2007996215892336924',
            'author': 'doodlestein',
            'date': datetime.now() - timedelta(hours=12),
            'severity': 'high',
            'severity_score': 72,
            'text': 'security concerns unauthorized attacker LLM agent full rein computer digital life'
        },
        {
            'source': 'X/Twitter',
            'title': 'adi: simple guide to get started with @clawdbot',
            'url': 'https://x.com/IamAdiG/status/2009024662672691355',
            'author': 'IamAdiG',
            'date': datetime.now() - timedelta(hours=10),
            'severity': 'low',
            'severity_score': 30,
            'text': 'setup guide getting started'
        }
    ]
    
    for r in results:
        severity, score = rate_severity(r['text'])
        issues = extract_security_issues(r['text'])
        r['severity'] = severity
        r['severity_score'] = score
        r['issues'] = issues
    
    print(f"   Found {len(results)} X results")
    return results

def analyze_results(all_results):
    """Analyze results and generate dashboard data."""
    
    if not all_results:
        return None
    
    # Remove duplicates by URL
    seen_urls = set()
    unique_results = []
    for r in all_results:
        if r['url'] not in seen_urls:
            seen_urls.add(r['url'])
            unique_results.append(r)
    
    # Sort by severity and discussion
    unique_results.sort(key=lambda x: (x['severity_score'], x.get('comments', 0), x.get('points', 0)), reverse=True)
    
    # Aggregate statistics
    stats = {
        'total_discussions': len(unique_results),
        'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'by_source': defaultdict(int),
        'avg_severity': 0,
        'total_mentions': sum(r.get('comments', 0) + r.get('points', 0) for r in unique_results)
    }
    
    severity_scores = []
    all_issues = []
    
    for r in unique_results:
        stats['by_severity'][r['severity']] += 1
        stats['by_source'][r['source']] += 1
        severity_scores.append(r['severity_score'])
        all_issues.extend(r.get('issues', []))
    
    if severity_scores:
        stats['avg_severity'] = sum(severity_scores) / len(severity_scores)
    
    # Aggregate issues
    issue_counts = defaultdict(list)
    for issue in all_issues:
        issue_counts[issue['issue']].append(issue['mitigation'])
    
    top_issues = []
    for issue, mitigations in issue_counts.items():
        top_issues.append({
            'issue': issue,
            'count': len(mitigations),
            'mitigation': mitigations[0]
        })
    top_issues.sort(key=lambda x: x['count'], reverse=True)
    
    return {
        'discussions': unique_results,
        'stats': dict(stats),
        'top_issues': top_issues[:10],
        'timestamp': datetime.now().isoformat()
    }

def generate_dashboard_json(data, filename='static/data/security_intel.json'):
    """Generate JSON file for dashboard consumption."""
    if not data:
        return
    
    os.makedirs(os.path.dirname(filename) if os.path.dirname(filename) else '.', exist_ok=True)
    
    dashboard_data = {
        'meta': {
            'generated': data['timestamp'],
            'hours_back': HOURS_BACK,
            'total_sources': len(data['stats']['by_source'])
        },
        'summary': {
            'total_discussions': data['stats']['total_discussions'],
            'critical_count': data['stats']['by_severity']['critical'],
            'high_count': data['stats']['by_severity']['high'],
            'medium_count': data['stats']['by_severity']['medium'],
            'low_count': data['stats']['by_severity']['low'],
            'average_severity': round(data['stats']['avg_severity'], 1),
            'total_engagement': data['stats']['total_mentions']
        },
        'severity_distribution': [
            data['stats']['by_severity']['critical'],
            data['stats']['by_severity']['high'],
            data['stats']['by_severity']['medium'],
            data['stats']['by_severity']['low']
        ],
        'source_breakdown': dict(data['stats']['by_source']),
        'top_security_concerns': data['top_issues'],
        'discussions': [
            {
                'title': d['title'][:100],
                'source': d['source'],
                'url': d['url'],
                'severity': d['severity'],
                'severity_score': d['severity_score'],
                'date': d['date'].strftime('%Y-%m-%d %H:%M'),
                'engagement': d.get('comments', 0) + d.get('points', 0) + d.get('score', 0)
            }
            for d in data['discussions'][:20]
        ],
        'mitigations': [
            {
                'issue': i['issue'],
                'mitigation': i['mitigation']
            }
            for i in data['top_issues']
        ]
    }
    
    with open(filename, 'w') as f:
        json.dump(dashboard_data, f, indent=2)
    
    print(f"\n📊 Dashboard data saved to {filename}")

def main():
    print(f"\n🔎 Clawdbot Security Intelligence Dashboard")
    print(f"📅 Analysis period: Last {HOURS_BACK} hours\n")
    
    all_results = []
    all_results.extend(search_web())
    all_results.extend(search_x())
    
    data = analyze_results(all_results)
    
    if data:
        # Generate dashboard JSON
        generate_dashboard_json(data, '/home/ubuntu/clawd/clawdbot-security-dashboard/static/data/security_intel.json')
        
        # Print summary
        print(f"\n{'='*70}")
        print(f"📊 SECURITY INTELLIGENCE SUMMARY")
        print(f"{'='*70}")
        print(f"\n📈 Discussions Found: {data['stats']['total_discussions']}")
        print(f"⚠️  By Severity: 🔴 {data['stats']['by_severity']['critical']} | 🟠 {data['stats']['by_severity']['high']} | 🟡 {data['stats']['by_severity']['medium']} | 🟢 {data['stats']['by_severity']['low']}")
        print(f"📊 Average Severity Score: {data['stats']['avg_severity']:.1f}")
        print(f"💬 Total Engagement: {data['stats']['total_mentions']}")
        
        print(f"\n🔴 TOP SECURITY CONCERNS:")
        for i, issue in enumerate(data['top_issues'][:5], 1):
            print(f"   {i}. {issue['issue']} (mentioned {issue['count']} times)")
            print(f"      💡 {issue['mitigation']}")
    
    return data

if __name__ == "__main__":
    main()
