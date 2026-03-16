# Threat Intelligence Enrichment Service

Batch enrichment service that queries ClickHouse for security events (blocked IPs, failed authentication attempts, DNS blocks), enriches them with threat intelligence data, and stores results back to ClickHouse for query-time joins.

## Architecture

```
ClickHouse (security events)
    ↓ (query IPs needing enrichment)
Enrichment Service
    ↓ (call threat intel APIs)
AbuseIPDB + VirusTotal + AlienVault OTX
    ↓ (store enriched data)
ClickHouse (threat_intel.enrichments table)
    ↓ (query-time LEFT JOIN)
Agent Query Tools + MCP Server
```

## Features

- **Batch Processing**: Queries ClickHouse for IPs needing enrichment every 30 minutes
- **Multiple Sources**:
  - pfSense blocked IPs (firewall blocks)
  - Failed SSH authentication attempts
  - DNS blocks from AdGuard Home
- **Rate Limiting**: 5-second delays between API calls to respect free tier limits
- **Caching**: File-based cache (24h TTL) shared with agent tools
- **Smart Re-enrichment**: Only enriches IPs that are:
  - New (not seen before)
  - Stale (enrichment older than 24 hours)
- **Prometheus Metrics**: Exposes metrics on port 9006

## Setup

### 1. Initialize Schema

Create the ClickHouse database and tables:

```bash
./scripts/init-threat-intel-schema.sh
```

This creates:
- `threat_intel.enrichments` table (ReplacingMergeTree)
- `threat_intel.enrichments_latest` materialized view (latest enrichment per IP)

### 2. Get API Keys

**AbuseIPDB** (Free tier: 1000 requests/day):
1. Sign up at https://www.abuseipdb.com/
2. Go to Account → API → Create Key
3. Copy your API key

**VirusTotal** (Free tier: 500 requests/day):
1. Sign up at https://www.virustotal.com/
2. Go to Profile → API Key
3. Copy your API key

**AlienVault OTX** (Free, no strict limits):
1. Sign up at https://otx.alienvault.com/
2. Go to Settings → API Integration
3. Copy your OTX Key

### 3. Configure Environment

Add to `.env` file:

```bash
ABUSEIPDB_API_KEY=your-abuseipdb-key-here
VIRUSTOTAL_API_KEY=your-virustotal-key-here
ALIENVAULT_API_KEY=your-alienvault-key-here
```

### 4. Deploy

```bash
docker compose up -d threat-intel-enricher
```

### 5. Verify

```bash
# Check logs
docker logs -f fl-threat-intel-enricher

# Check metrics
curl http://localhost:9006/metrics

# Query enrichment data
docker exec signoz-clickhouse clickhouse-client --query "
  SELECT ip, threat_score, recommendation, enriched_at
  FROM threat_intel.enrichments_latest
  ORDER BY threat_score DESC
  LIMIT 10
"
```

## Configuration

Environment variables (with defaults):

| Variable | Default | Description |
|----------|---------|-------------|
| `CLICKHOUSE_URL` | `http://clickhouse:8123` | ClickHouse HTTP endpoint |
| `ENRICHMENT_BATCH_SIZE` | `50` | Max IPs to enrich per batch |
| `ENRICHMENT_INTERVAL_MINUTES` | `30` | Minutes between enrichment runs |
| `ENRICHMENT_LOOKBACK_HOURS` | `24` | How far back to look for events |
| `ENRICHMENT_MAX_AGE_HOURS` | `24` | Re-enrich if older than this |
| `METRICS_PORT` | `9006` | Prometheus metrics port |

## Database Schema

### threat_intel.enrichments

Main table storing all enrichment results:

| Column | Type | Description |
|--------|------|-------------|
| `ip` | String | IP address |
| `enriched_at` | DateTime64(3) | Timestamp of enrichment |
| `abuseipdb_score` | Int32 | AbuseIPDB confidence score (0-100) |
| `abuseipdb_reports` | Int32 | Total abuse reports |
| `virustotal_malicious` | Int32 | Number of malicious verdicts |
| `virustotal_suspicious` | Int32 | Number of suspicious verdicts |
| `alienvault_pulse_count` | Int32 | Number of OTX pulses |
| `threat_score` | Int32 | Composite threat score (0-100) |
| `is_malicious` | Bool | True if threat_score >= 50 |
| `confidence` | String | 'low', 'medium', 'high' |
| `recommendation` | String | 'allow', 'monitor', 'alert', 'block' |
| `error_sources` | Array(String) | Sources that had errors |

Uses `ReplacingMergeTree` to keep latest enrichment per IP.

### threat_intel.enrichments_latest

Materialized view with latest enrichment per IP:

```sql
SELECT * FROM threat_intel.enrichments_latest
WHERE ip = '1.2.3.4'
```

## Prometheus Metrics

Exposed on port 9006:

```prometheus
# Total enrichments performed
threat_intel_enrichments_total{status="success|no_data|error"}

# Enrichment duration
threat_intel_enrichment_duration_seconds

# Cache hits by source
threat_intel_cache_hits_total{source="abuseipdb|virustotal|alienvault"}

# API errors
threat_intel_api_errors_total{source="...",error_type="..."}

# Current state
threat_intel_pending_ips         # IPs waiting to be enriched
threat_intel_last_run_timestamp  # Unix timestamp of last run
threat_intel_last_run_duration_seconds
```

## Rate Limit Management

**Free Tier Limits:**
- AbuseIPDB: 1000/day = ~42/hour
- VirusTotal: 500/day = ~21/hour
- AlienVault: No strict limit

**Strategy:**
- 24-hour caching (shared with agent tools)
- 5-second delay between API calls
- Batch size of 50 IPs per run
- Runs every 30 minutes
- **Max throughput**: ~360 unique IPs/day (50 batch × 2 runs/hour × 24h / 7 retries)

If you exceed rate limits:
- Reduce `ENRICHMENT_BATCH_SIZE`
- Increase `ENRICHMENT_INTERVAL_MINUTES`
- Consider paid tiers for higher limits

## Integration with Agent Tools

The enrichment service populates data that agent query tools consume via LEFT JOINs:

```python
# agent/tools/threat_intel_queries.py
from langchain_core.tools import tool

@tool
def query_enriched_firewall_blocks(hours: int = 24, min_threat_score: int = 50):
    """
    Query pfSense blocks with threat intelligence enrichment.

    Joins otel_logs with threat_intel.enrichments_latest to show
    which blocked IPs are known threats.
    """
    query = f"""
    SELECT
        logs.timestamp,
        logs.src_ip,
        logs.dst_ip,
        logs.dst_port,
        enrichment.threat_score,
        enrichment.is_malicious,
        enrichment.recommendation,
        enrichment.abuseipdb_score,
        enrichment.virustotal_malicious
    FROM otel_logs logs
    LEFT JOIN threat_intel.enrichments_latest enrichment
        ON logs.src_ip = enrichment.ip
    WHERE logs.timestamp >= now() - INTERVAL {hours} HOUR
      AND logs.service_name = 'filterlog'
      AND logs.action = 'block'
      AND (enrichment.threat_score >= {min_threat_score} OR enrichment.threat_score IS NULL)
    ORDER BY enrichment.threat_score DESC, logs.timestamp DESC
    LIMIT 100
    """
    return execute_clickhouse_query(query)
```

## Troubleshooting

**No IPs being enriched:**
- Check logs for query errors
- Verify ClickHouse is accessible: `docker exec signoz-clickhouse clickhouse-client --query "SELECT 1"`
- Ensure security events exist in `otel_logs` table
- Check `threat_intel_pending_ips` metric

**Rate limit errors:**
- Check cache is working (look for "cache hit" in logs)
- Reduce batch size or increase interval
- Wait until quota resets (usually midnight UTC)
- Monitor daily usage on provider dashboards

**High memory usage:**
- Reduce `ENRICHMENT_BATCH_SIZE`
- The service loads all enrichment logic in memory

**Schema not found:**
- Run `./scripts/init-threat-intel-schema.sh`
- Verify with: `docker exec signoz-clickhouse clickhouse-client --query "SHOW DATABASES"`

## Development

To run locally for testing:

```bash
cd services/threat-intel-enricher

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export CLICKHOUSE_URL=http://localhost:8123
export ABUSEIPDB_API_KEY=...
export VIRUSTOTAL_API_KEY=...
export ALIENVAULT_API_KEY=...

# Run enricher
python enricher.py
```

## Future Enhancements

- [ ] Domain/URL enrichment (not just IPs)
- [ ] Bulk lookup support (where APIs allow)
- [ ] Redis cache for multi-instance deployments
- [ ] Configurable enrichment sources per IP type
- [ ] Historical trending (track threat score changes over time)
- [ ] Automated blocking integration (add to pfSense blocklist)
- [ ] Web UI for manual lookups
- [ ] Export to STIX/TAXII formats
