"""
Threat Intelligence Enrichment Service

Batch enrichment service that:
1. Queries ClickHouse for IPs needing enrichment
2. Calls threat intelligence APIs
3. Stores results back to ClickHouse
4. Exposes Prometheus metrics
"""

import json
import os
import time
import logging
from typing import List, Dict, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass
import asyncio

import httpx
from prometheus_client import Counter, Gauge, Histogram, start_http_server
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from threat_intel import ThreatIntelligence

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Prometheus metrics
enrichments_total = Counter('threat_intel_enrichments_total', 'Total IP enrichments performed', ['status'])
enrichment_duration = Histogram('threat_intel_enrichment_duration_seconds', 'Time to enrich an IP')
cache_hits = Counter('threat_intel_cache_hits_total', 'Cache hits by source', ['source'])
api_errors = Counter('threat_intel_api_errors_total', 'API errors by source', ['source', 'error_type'])
pending_ips = Gauge('threat_intel_pending_ips', 'Number of IPs pending enrichment')
last_run_timestamp = Gauge('threat_intel_last_run_timestamp', 'Unix timestamp of last enrichment run')
last_run_duration = Gauge('threat_intel_last_run_duration_seconds', 'Duration of last enrichment run')


@dataclass
class EnrichmentConfig:
    """Configuration for enrichment service."""
    clickhouse_url: str
    abuseipdb_key: Optional[str]
    virustotal_key: Optional[str]
    alienvault_key: Optional[str]
    cache_dir: str
    batch_size: int = 20
    interval_minutes: int = 60
    lookback_hours: int = 24
    max_age_hours: int = 168   # Re-enrich after 7 days, not 24h
    min_block_count: int = 5   # Ignore IPs with fewer than this many blocks
    daily_budget: int = 900    # Hard cap on AbuseIPDB calls per UTC day

    @classmethod
    def from_env(cls) -> 'EnrichmentConfig':
        """Load configuration from environment variables."""
        return cls(
            clickhouse_url=os.getenv('CLICKHOUSE_URL', 'http://clickhouse:8123'),
            abuseipdb_key=os.getenv('ABUSEIPDB_API_KEY'),
            virustotal_key=os.getenv('VIRUSTOTAL_API_KEY'),
            alienvault_key=os.getenv('ALIENVAULT_API_KEY'),
            cache_dir=os.getenv('THREAT_INTEL_CACHE_DIR', '/data/threat_intel_cache'),
            batch_size=int(os.getenv('ENRICHMENT_BATCH_SIZE', '20')),
            interval_minutes=int(os.getenv('ENRICHMENT_INTERVAL_MINUTES', '60')),
            lookback_hours=int(os.getenv('ENRICHMENT_LOOKBACK_HOURS', '24')),
            max_age_hours=int(os.getenv('ENRICHMENT_MAX_AGE_HOURS', '168')),
            min_block_count=int(os.getenv('ENRICHMENT_MIN_BLOCK_COUNT', '5')),
            daily_budget=int(os.getenv('ABUSEIPDB_DAILY_BUDGET', '900')),
        )


class ClickHouseClient:
    """Simple ClickHouse client for enrichment storage."""

    def __init__(self, url: str):
        self.url = url.rstrip('/')
        self.client = httpx.Client(timeout=30.0)

    def query(self, sql: str) -> List[Dict]:
        """Execute query and return results as list of dicts."""
        try:
            response = self.client.post(
                self.url,
                params={'query': sql, 'default_format': 'JSONEachRow'},
                headers={'Content-Type': 'text/plain'}
            )
            response.raise_for_status()

            if not response.text.strip():
                return []

            return [json.loads(line) for line in response.text.strip().split('\n') if line.strip()]
        except Exception as e:
            logger.error(f"ClickHouse query error: {e}")
            return []

    def execute(self, sql: str) -> bool:
        """Execute statement without returning results."""
        try:
            response = self.client.post(
                self.url,
                params={'query': sql},
                headers={'Content-Type': 'text/plain'}
            )
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"ClickHouse execute error: {e}")
            return False

    def insert_enrichment(self, enrichment: Dict) -> bool:
        """Insert enrichment result into ClickHouse."""
        sources = enrichment.get('sources', {})
        assessment = enrichment.get('threat_assessment', {})

        # Extract error sources
        error_sources = []
        for source_name, source_data in sources.items():
            if isinstance(source_data, dict) and 'error' in source_data:
                error_sources.append(source_name)

        # Build INSERT statement
        sql = f"""
        INSERT INTO threat_intel.enrichments FORMAT JSONEachRow
        {{"ip": "{enrichment['ip']}",
         "enriched_at": "{enrichment['enriched_at']}",
         "abuseipdb_score": {sources.get('abuseipdb', {}).get('abuse_confidence_score', 0)},
         "abuseipdb_reports": {sources.get('abuseipdb', {}).get('total_reports', 0)},
         "abuseipdb_distinct_users": {sources.get('abuseipdb', {}).get('num_distinct_users', 0)},
         "abuseipdb_country_code": "{sources.get('abuseipdb', {}).get('country_code', '')}",
         "abuseipdb_usage_type": "{sources.get('abuseipdb', {}).get('usage_type', '')}",
         "abuseipdb_is_whitelisted": {str(sources.get('abuseipdb', {}).get('is_whitelisted', False)).lower()},
         "virustotal_malicious": {sources.get('virustotal', {}).get('malicious', 0)},
         "virustotal_suspicious": {sources.get('virustotal', {}).get('suspicious', 0)},
         "virustotal_harmless": {sources.get('virustotal', {}).get('harmless', 0)},
         "virustotal_reputation": {sources.get('virustotal', {}).get('reputation', 0)},
         "virustotal_as_owner": "{sources.get('virustotal', {}).get('as_owner', '')}",
         "virustotal_country": "{sources.get('virustotal', {}).get('country', '')}",
         "alienvault_pulse_count": {sources.get('alienvault', {}).get('pulse_count', 0)},
         "alienvault_pulses": {sources.get('alienvault', {}).get('pulses', [])},
         "alienvault_country_code": "{sources.get('alienvault', {}).get('country_code', '')}",
         "threat_score": {assessment.get('threat_score', 0)},
         "is_malicious": {str(assessment.get('is_malicious', False)).lower()},
         "confidence": "{assessment.get('confidence', 'low')}",
         "categories": {assessment.get('categories', [])},
         "recommendation": "{assessment.get('recommendation', 'allow')}",
         "error_sources": {error_sources}
        }}
        """

        return self.execute(sql)


class ThreatIntelEnricher:
    """Main enrichment service."""

    def __init__(self, config: EnrichmentConfig):
        self.config = config
        self.ch_client = ClickHouseClient(config.clickhouse_url)
        self.threat_intel = ThreatIntelligence(
            abuseipdb_key=config.abuseipdb_key,
            virustotal_key=config.virustotal_key,
            alienvault_key=config.alienvault_key,
            cache_dir=config.cache_dir
        )
        self._budget_file = os.path.join(config.cache_dir, "abuseipdb_daily_budget.txt")

    def _budget_remaining(self) -> int:
        """Return remaining AbuseIPDB calls for today (UTC). Resets at midnight UTC."""
        today = datetime.utcnow().strftime("%Y-%m-%d")
        try:
            with open(self._budget_file) as f:
                date_str, count_str = f.read().strip().split(",")
            if date_str == today:
                return max(0, self.config.daily_budget - int(count_str))
        except Exception:
            pass
        return self.config.daily_budget

    def _budget_consume(self, count: int = 1):
        """Record that we used `count` AbuseIPDB calls today."""
        today = datetime.utcnow().strftime("%Y-%m-%d")
        used = self.config.daily_budget - self._budget_remaining()
        os.makedirs(os.path.dirname(self._budget_file), exist_ok=True)
        with open(self._budget_file, "w") as f:
            f.write(f"{today},{used + count}")

    def get_ips_needing_enrichment(self) -> Set[str]:
        """Query ClickHouse for IPs that need enrichment."""
        logger.info("Querying for IPs needing enrichment...")

        # Subquery: IPs already enriched recently (use raw table, not AggregatingMergeTree MV)
        already_enriched = f"""
            SELECT DISTINCT ip FROM threat_intel.enrichments
            WHERE toDateTime(enriched_at) >= now() - INTERVAL {self.config.max_age_hours} HOUR
        """

        # Query 1: Blocked IPs from pfSense filterlog — only IPs with enough blocks to be worth enriching
        blocked_query = f"""
        SELECT attributes_string['pfsense.src_ip'] as ip
        FROM signoz_logs.logs_v2
        WHERE toDateTime(timestamp / 1000000000) >= now() - INTERVAL {self.config.lookback_hours} HOUR
          AND resources_string['service.name'] = 'filterlog'
          AND attributes_string['pfsense.action'] = 'block'
          AND attributes_string['pfsense.src_ip'] != ''
          AND attributes_string['pfsense.src_ip'] NOT IN ({already_enriched})
        GROUP BY ip
        HAVING count() >= {self.config.min_block_count}
        ORDER BY count() DESC
        LIMIT {self.config.batch_size}
        """

        # Query 2: Failed SSH attempts (parse IP from log body)
        ssh_query = f"""
        SELECT DISTINCT extract(body, 'from ([0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}})') as ip
        FROM signoz_logs.logs_v2
        WHERE toDateTime(timestamp / 1000000000) >= now() - INTERVAL {self.config.lookback_hours} HOUR
          AND (body LIKE '%Failed password%' OR body LIKE '%Invalid user%')
          AND ip != ''
          AND ip NOT IN ({already_enriched})
        LIMIT {self.config.batch_size}
        """

        # Query 3: ntopng flow alerts (top external IPs with alerts)
        ntopng_query = f"""
        SELECT DISTINCT attributes_string['remote_ip'] as ip
        FROM signoz_logs.logs_v2
        WHERE toDateTime(timestamp / 1000000000) >= now() - INTERVAL {self.config.lookback_hours} HOUR
          AND resources_string['service.name'] = 'ntopng'
          AND attributes_string['alert_severity'] IN ('error', 'warning')
          AND attributes_string['remote_ip'] != ''
          AND ip NOT IN ({already_enriched})
        LIMIT {self.config.batch_size}
        """

        ips = set()

        for query_name, query in [
            ('pfsense_blocked', blocked_query),
            ('ssh_failed', ssh_query),
            ('ntopng_alerts', ntopng_query)
        ]:
            try:
                results = self.ch_client.query(query)
                query_ips = {r['ip'] for r in results if r.get('ip')}
                logger.info(f"Found {len(query_ips)} IPs from {query_name} query")
                ips.update(query_ips)
            except Exception as e:
                logger.error(f"Error querying {query_name} IPs: {e}")

        # Filter out private IPs
        ips = {ip for ip in ips if not self._is_private_ip(ip)}

        logger.info(f"Total {len(ips)} unique public IPs need enrichment")
        pending_ips.set(len(ips))
        return ips

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal."""
        parts = ip.split('.')
        if len(parts) != 4:
            return True

        try:
            first = int(parts[0])
            second = int(parts[1])

            # RFC1918 private ranges
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            # Loopback
            if first == 127:
                return True
            # Link-local
            if first == 169 and second == 254:
                return True

            return False
        except ValueError:
            return True

    def enrich_ip(self, ip: str) -> Optional[Dict]:
        """Enrich a single IP."""
        with enrichment_duration.time():
            try:
                logger.info(f"Enriching {ip}...")
                result = self.threat_intel.enrich_ip(ip)

                if result:
                    enrichments_total.labels(status='success').inc()
                    return result
                else:
                    enrichments_total.labels(status='no_data').inc()
                    return None

            except Exception as e:
                logger.error(f"Error enriching {ip}: {e}")
                enrichments_total.labels(status='error').inc()
                api_errors.labels(source='enrichment', error_type=type(e).__name__).inc()
                return None

    def run_enrichment_batch(self):
        """Run a batch of enrichments."""
        start_time = time.time()
        logger.info("Starting enrichment batch...")

        try:
            ips = self.get_ips_needing_enrichment()

            if not ips:
                logger.info("No IPs need enrichment")
                return

            enriched_count = 0
            failed_count = 0

            for ip in ips:
                remaining = self._budget_remaining()
                if remaining <= 0:
                    logger.warning(f"AbuseIPDB daily budget exhausted ({self.config.daily_budget}/day). Stopping batch.")
                    break

                result = self.enrich_ip(ip)
                self._budget_consume(1)

                if result:
                    # Store in ClickHouse
                    if self.ch_client.insert_enrichment(result):
                        enriched_count += 1
                        logger.info(f"Stored enrichment for {ip} - Score: {result['threat_assessment']['threat_score']} (budget remaining: {self._budget_remaining()})")
                    else:
                        failed_count += 1
                        logger.error(f"Failed to store enrichment for {ip}")
                else:
                    failed_count += 1

                # Rate limiting: 5 seconds between API calls
                time.sleep(5)

            duration = time.time() - start_time
            logger.info(f"Enrichment batch complete: {enriched_count} enriched, {failed_count} failed in {duration:.1f}s")

            last_run_timestamp.set(time.time())
            last_run_duration.set(duration)

        except Exception as e:
            logger.error(f"Error in enrichment batch: {e}")
            api_errors.labels(source='batch', error_type=type(e).__name__).inc()


def main():
    """Main entry point."""
    logger.info("Starting Threat Intelligence Enrichment Service...")

    # Load configuration
    config = EnrichmentConfig.from_env()
    logger.info(f"Configuration: batch_size={config.batch_size}, "
                f"interval={config.interval_minutes}min, "
                f"lookback={config.lookback_hours}h")

    # Start Prometheus metrics server
    metrics_port = int(os.getenv('METRICS_PORT', '9006'))
    start_http_server(metrics_port)
    logger.info(f"Metrics server started on port {metrics_port}")

    # Create enricher
    enricher = ThreatIntelEnricher(config)

    # Run initial enrichment
    enricher.run_enrichment_batch()

    # Schedule periodic enrichment
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        enricher.run_enrichment_batch,
        trigger=IntervalTrigger(minutes=config.interval_minutes),
        id='enrichment_batch',
        name='Run enrichment batch',
        replace_existing=True
    )
    scheduler.start()
    logger.info(f"Scheduler started - will run every {config.interval_minutes} minutes")

    # Keep running
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        scheduler.shutdown()


if __name__ == '__main__':
    main()
