# Threat Intelligence Enrichment

Enriches security events with threat intelligence from multiple sources.

## Features

**Threat Intel Sources:**
- **AbuseIPDB** - IP reputation and abuse reports (1000 requests/day free)
- **VirusTotal** - IP/domain/URL reputation (500 requests/day free)
- **AlienVault OTX** - Open threat exchange (no strict limits)

**Enrichment Capabilities:**
- IP reputation scoring (0-100)
- Threat categorization (malware, abuse, IOC)
- Composite threat assessment
- Action recommendations (allow, monitor, alert, block)
- 24-hour caching to respect rate limits

**Integration Points:**
- Enrich pfSense blocked IPs
- Enrich SSH failed login attempts
- Enrich CrowdSec alerts
- Enrich DNS blocks from AdGuard
- Enrich ntopng security alerts

## Setup

### 1. Get API Keys

**AbuseIPDB** (Free tier: 1000/day):
1. Go to https://www.abuseipdb.com/
2. Create account
3. Go to Account → API → Create Key
4. Copy your API key

**VirusTotal** (Free tier: 500/day):
1. Go to https://www.virustotal.com/
2. Create account
3. Go to Profile → API Key
4. Copy your API key

**AlienVault OTX** (Free, no strict limits):
1. Go to https://otx.alienvault.com/
2. Create account
3. Go to Settings → API Integration
4. Copy your OTX Key

### 2. Configure Environment

Create `.env` file:

```bash
# Threat Intelligence API Keys
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
ALIENVAULT_API_KEY=your_alienvault_key_here

# Cache settings
THREAT_INTEL_CACHE_DIR=/data/cache
THREAT_INTEL_CACHE_TTL=86400  # 24 hours
```

### 3. Test Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Test IP lookup
python threat_intel.py 8.8.8.8

# Test with known malicious IP
python threat_intel.py 45.142.212.61
```

### 4. Integration with SigNoz

The threat intel module can be used in two ways:

**Option A: As a Python Library** (Recommended for agent integration)

```python
from agent.tools.threat_intel import check_ip_reputation

result = check_ip_reputation('1.2.3.4')
print(f"Threat Score: {result['threat_assessment']['threat_score']}")
print(f"Recommendation: {result['threat_assessment']['recommendation']}")
```

**Option B: CLI Tool** (For ad-hoc queries)

```bash
python threat_intel.py <IP_ADDRESS>
```

## Enrichment Output

```json
{
  "ip": "45.142.212.61",
  "enriched_at": "2026-03-15T18:30:00",
  "sources": {
    "abuseipdb": {
      "source": "abuseipdb",
      "ip": "45.142.212.61",
      "abuse_confidence_score": 100,
      "total_reports": 847,
      "num_distinct_users": 143,
      "country_code": "RU",
      "usage_type": "Data Center/Web Hosting/Transit"
    },
    "virustotal": {
      "source": "virustotal",
      "ip": "45.142.212.61",
      "malicious": 12,
      "suspicious": 3,
      "harmless": 65,
      "reputation": -42
    },
    "alienvault": {
      "source": "alienvault",
      "ip": "45.142.212.61",
      "pulse_count": 8,
      "pulses": [
        "Malicious IPs",
        "Brute Force Attacks",
        "SSH Scanners"
      ],
      "country_code": "RU"
    }
  },
  "threat_assessment": {
    "is_malicious": true,
    "confidence": "high",
    "threat_score": 87,
    "categories": ["abuse", "malware", "ioc"],
    "recommendation": "block"
  }
}
```

## Threat Scoring

**Composite Score Calculation:**
- AbuseIPDB abuse confidence score (0-100)
- VirusTotal detections (malicious * 10 + suspicious * 5)
- AlienVault pulse count (pulses * 10, max 100)
- Final score: Average of all available scores

**Threat Levels:**
- **0-24**: Clean (allow)
- **25-49**: Low risk (monitor)
- **50-74**: Medium risk (alert)
- **75-100**: High risk (block)

**Confidence Levels:**
- **High**: Score ≥75, multiple sources agree
- **Medium**: Score 50-74, some indicators
- **Low**: Score 25-49, limited indicators

## Rate Limit Management

**Free Tier Limits:**
- AbuseIPDB: 1000/day = ~42/hour = ~1.4 per 2 minutes
- VirusTotal: 500/day = ~21/hour = ~1 per 3 minutes
- AlienVault: No strict limit

**Caching Strategy:**
- All lookups cached for 24 hours
- Cache shared across all queries
- File-based cache (no Redis required)
- Automatic cache expiration

**Rate Limit Handling:**
- Returns cached result if available
- Returns error if rate limited
- Recommend spacing automated queries 5+ minutes apart

## Use Cases

### 1. Enrich pfSense Blocks

Query IPs that pfSense blocked:

```python
from agent.tools.threat_intel import check_ip_reputation

blocked_ips = get_blocked_ips_from_signoz()  # Your query
for ip in blocked_ips:
    intel = check_ip_reputation(ip)
    if intel['threat_assessment']['is_malicious']:
        alert(f"Known malicious IP blocked: {ip}")
```

### 2. Prioritize SSH Failures

Check if failed SSH logins are from known attackers:

```python
ssh_failures = get_ssh_failures()
for event in ssh_failures:
    intel = check_ip_reputation(event['source_ip'])
    if intel['threat_assessment']['threat_score'] > 75:
        priority_alert(event)  # High-priority alert
```

### 3. Validate DNS Blocks

Confirm AdGuard DNS blocks are actually malicious:

```python
dns_blocks = get_dns_blocks()
for block in dns_blocks:
    intel = check_ip_reputation(block['server_ip'])
    if intel['threat_assessment']['threat_score'] < 25:
        false_positive_review(block)  # Might be false positive
```

## Advanced: Batch Enrichment

For enriching historical data:

```python
import time
from agent.tools.threat_intel import ThreatIntelligence

intel = ThreatIntelligence(
    abuseipdb_key="...",
    virustotal_key="...",
    alienvault_key="..."
)

ips = get_all_suspicious_ips()
for ip in ips:
    result = intel.enrich_ip(ip)
    store_enrichment(ip, result)
    time.sleep(5)  # Rate limiting
```

## API Key Security

**Best Practices:**
- Store keys in `.env` file (gitignored)
- Never commit keys to repository
- Use environment variables in production
- Rotate keys periodically
- Monitor API usage on provider dashboards

## Limitations

**Free Tier Restrictions:**
- Limited daily quotas
- No bulk API access
- Basic features only
- No SLA guarantees

**For Production:**
- Consider paid tiers for higher limits
- Implement robust error handling
- Monitor quota usage
- Have fallback logic if all sources unavailable

## Troubleshooting

**Rate Limit Errors:**
- Check cache is working (should see "cache hit" in logs)
- Reduce query frequency
- Wait until quota resets (usually midnight UTC)
- Consider paid tier if needed

**No Results:**
- Verify API keys are correct
- Check network connectivity
- Review logs for error messages
- Test with known malicious IP first

**Cache Issues:**
- Check `/tmp/threat_intel_cache` directory exists
- Verify write permissions
- Clear cache: `rm -rf /tmp/threat_intel_cache/*`

## Future Enhancements

- Redis caching for multi-instance deployments
- Bulk lookup support where available
- Domain and URL enrichment
- File hash lookups (VirusTotal)
- CVE intelligence
- Threat feed subscriptions
- Automated blocking integration
- Historical trending
- Web UI for manual lookups
