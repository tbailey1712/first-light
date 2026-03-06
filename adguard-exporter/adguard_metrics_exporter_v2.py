#!/usr/bin/env python3
"""
AdGuard DNS Analytics → SigNoz Exporter v2.0

Exports both METRICS and LOGS to SigNoz:
- Metrics: Client summaries, risk scores, counts (existing)
- Logs: Individual anomaly detections with full details (NEW)

Runs hourly after AdGuard log ingestion completes.

Deploy on AdGuard LXC at: /home/tbailey/adgh/adguard_metrics_exporter.py
"""

import sqlite3
import time
import logging
import json
from datetime import datetime
from typing import Dict, List, Tuple

from opentelemetry import metrics
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource

# NEW: Log export imports
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter

# Configuration
DB_PATH = "/home/tbailey/adgh/cache.db"
SIGNOZ_ENDPOINT = "192.168.2.106:4317"
EXPORT_INTERVAL_MS = 60000  # Export every 60 seconds during run

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AdGuardMetricsExporter:
    """Exports AdGuard DNS analytics to SigNoz as OTLP metrics + logs"""

    def __init__(self, db_path: str, signoz_endpoint: str):
        self.db_path = db_path
        self.conn = None

        # Setup OpenTelemetry Resource
        resource = Resource.create({
            "service.name": "adguard-metrics-exporter",
            "deployment.environment": "production",
            "host.name": "adguard.mcducklabs.com"
        })

        # Setup METRICS export (existing)
        self._setup_metrics(resource, signoz_endpoint)
        
        # NEW: Setup LOGS export
        self._setup_logs(resource, signoz_endpoint)

    def _setup_metrics(self, resource: Resource, endpoint: str):
        """Setup metrics export (existing functionality)"""
        exporter = OTLPMetricExporter(
            endpoint=endpoint,
            insecure=True
        )

        reader = PeriodicExportingMetricReader(
            exporter,
            export_interval_millis=EXPORT_INTERVAL_MS
        )

        provider = MeterProvider(resource=resource, metric_readers=[reader])
        metrics.set_meter_provider(provider)

        self.meter = metrics.get_meter("adguard-dns-analytics")
        self._create_metric_instruments()

    def _setup_logs(self, resource: Resource, endpoint: str):
        """Setup log export for anomalies (NEW)"""
        log_exporter = OTLPLogExporter(
            endpoint=endpoint,
            insecure=True
        )

        log_provider = LoggerProvider(resource=resource)
        log_provider.add_log_record_processor(
            BatchLogRecordProcessor(log_exporter)
        )

        # Create anomaly logger
        handler = LoggingHandler(
            level=logging.NOTSET,
            logger_provider=log_provider
        )

        self.anomaly_logger = logging.getLogger("adguard.anomalies")
        self.anomaly_logger.addHandler(handler)
        self.anomaly_logger.setLevel(logging.INFO)

    def _create_metric_instruments(self):
        """Create all metric instruments (existing)"""
        # Client metrics
        self.queries_counter = self.meter.create_counter(
            "adguard.queries.total",
            description="Total DNS queries per client (24h)",
            unit="queries"
        )

        self.blocks_counter = self.meter.create_counter(
            "adguard.blocks.total",
            description="Total blocked queries per client (24h)",
            unit="queries"
        )

        self.block_rate_gauge = self.meter.create_gauge(
            "adguard.block.rate",
            description="Percentage of queries blocked per client",
            unit="percent"
        )

        self.risk_score_gauge = self.meter.create_gauge(
            "adguard.client.risk_score",
            description="Client risk score (0-10)",
            unit="score"
        )

        # Anomaly metrics
        self.anomalies_counter = self.meter.create_counter(
            "adguard.anomalies.detected",
            description="Count of detected anomalies by type and severity",
            unit="anomalies"
        )

        # Domain metrics
        self.blocked_domains_counter = self.meter.create_counter(
            "adguard.blocked_domains.total",
            description="Top blocked domains",
            unit="blocks"
        )

        # Ingestion health
        self.ingestion_duration_histogram = self.meter.create_histogram(
            "adguard.ingestion.duration",
            description="Ingestion run duration",
            unit="seconds"
        )

        self.ingestion_records_counter = self.meter.create_counter(
            "adguard.ingestion.records",
            description="Records processed in ingestion",
            unit="records"
        )

    def connect_db(self):
        """Connect to AdGuard SQLite database"""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            logger.info(f"Connected to database: {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise

    def close_db(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")

    def export_client_metrics(self):
        """Export per-client query and block metrics from client_summary"""
        query = """
            SELECT
                cs.client_ip,
                c.client_name,
                cs.last_24h_queries,
                cs.last_24h_blocked,
                cs.last_24h_block_pct,
                cs.risk_score,
                cs.traffic_type
            FROM client_summary cs
            LEFT JOIN clients c ON c.client_ip = cs.client_ip
            WHERE cs.last_24h_queries > 0
            ORDER BY cs.last_24h_queries DESC
        """

        cursor = self.conn.execute(query)
        rows = cursor.fetchall()

        for row in rows:
            attributes = {
                "client.ip": row["client_ip"],
                "client.name": row["client_name"] or "unknown",
                "traffic.type": row["traffic_type"] or "unknown"
            }

            # Export metrics
            self.queries_counter.add(row["last_24h_queries"], attributes=attributes)
            self.blocks_counter.add(row["last_24h_blocked"], attributes=attributes)
            self.block_rate_gauge.set(row["last_24h_block_pct"], attributes=attributes)
            self.risk_score_gauge.set(row["risk_score"], attributes=attributes)

        logger.info(f"Exported metrics for {len(rows)} clients")

    def export_anomaly_metrics(self):
        """Export anomaly detection metrics from last 24h"""
        query = """
            SELECT
                anomaly_type,
                severity,
                COUNT(*) as count
            FROM anomalies
            WHERE detected_at > strftime('%s', 'now', '-1 day')
            GROUP BY anomaly_type, severity
        """

        cursor = self.conn.execute(query)
        rows = cursor.fetchall()

        for row in rows:
            attributes = {
                "anomaly.type": row["anomaly_type"],
                "severity": row["severity"]
            }
            self.anomalies_counter.add(row["count"], attributes=attributes)

        logger.info(f"Exported {len(rows)} anomaly metric groups")

    def export_anomaly_logs(self):
        """
        NEW: Export individual anomalies as structured logs.
        
        Exports unacknowledged anomalies from last hour with full details.
        These become searchable logs in SigNoz with all metadata.
        """
        query = """
            SELECT
                detected_at,
                anomaly_type,
                client_ip,
                severity,
                description,
                metadata,
                confidence
            FROM anomalies
            WHERE detected_at > strftime('%s', 'now', '-1 hour')
            AND acknowledged = 0
            ORDER BY detected_at DESC
        """

        cursor = self.conn.execute(query)
        rows = cursor.fetchall()

        anomaly_count = 0
        for row in rows:
            try:
                # Parse metadata JSON
                metadata = {}
                if row["metadata"]:
                    try:
                        metadata = json.loads(row["metadata"])
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse metadata for anomaly: {row['description']}")

                # Map severity to log level
                severity_map = {
                    "low": logging.INFO,
                    "medium": logging.WARNING,
                    "high": logging.ERROR,
                    "critical": logging.CRITICAL
                }
                log_level = severity_map.get(row["severity"], logging.WARNING)

                # Create structured log with all details
                extra_attrs = {
                    "anomaly.type": row["anomaly_type"],
                    "anomaly.client_ip": row["client_ip"],
                    "anomaly.severity": row["severity"],
                    "anomaly.confidence": float(row["confidence"]),
                    "anomaly.detected_at": int(row["detected_at"])
                }

                # Add metadata fields as separate attributes for better querying
                if "domain" in metadata:
                    extra_attrs["anomaly.domain"] = metadata["domain"]
                if "entropy" in metadata:
                    extra_attrs["anomaly.entropy"] = float(metadata["entropy"])
                if "query_count" in metadata:
                    extra_attrs["anomaly.query_count"] = int(metadata["query_count"])
                if "occurrence_count" in metadata:
                    extra_attrs["anomaly.occurrence_count"] = int(metadata["occurrence_count"])
                if "blocklist" in metadata:
                    extra_attrs["anomaly.blocklist"] = metadata["blocklist"]

                # Log the anomaly with description as message body
                self.anomaly_logger.log(
                    log_level,
                    row["description"],
                    extra=extra_attrs
                )

                anomaly_count += 1

            except Exception as e:
                logger.error(f"Failed to export anomaly log: {e}", exc_info=True)
                continue

        logger.info(f"Exported {anomaly_count} anomaly logs (from last hour)")
        return anomaly_count

    def export_blocked_domains(self, limit: int = 20):
        """Export top blocked domains from last 24h"""
        query = """
            SELECT
                d.full_domain,
                COUNT(*) as block_count,
                COUNT(DISTINCT v.client_id) as unique_clients
            FROM visits v
            JOIN domains d ON d.id = v.domain_id
            WHERE v.is_filtered = 1
              AND v.t > strftime('%s', 'now', '-1 day')
            GROUP BY d.full_domain
            ORDER BY block_count DESC
            LIMIT ?
        """

        try:
            cursor = self.conn.execute(query, (limit,))
            rows = cursor.fetchall()

            for row in rows:
                attributes = {
                    "domain": row["full_domain"],
                    "unique_clients": str(row["unique_clients"])
                }
                self.blocked_domains_counter.add(row["block_count"], attributes=attributes)

            logger.info(f"Exported top {len(rows)} blocked domains")
        except sqlite3.OperationalError as e:
            # Handle case where visits table doesn't exist or schema changed
            logger.warning(f"Could not export blocked domains: {e}")

    def export_ingestion_health(self):
        """Export ingestion pipeline health metrics"""
        query = """
            SELECT
                duration_seconds,
                records_inserted,
                records_skipped,
                status
            FROM ingestion_runs
            ORDER BY start_time DESC
            LIMIT 1
        """

        try:
            cursor = self.conn.execute(query)
            row = cursor.fetchone()

            if row:
                attributes = {"status": row["status"]}

                if row["duration_seconds"]:
                    self.ingestion_duration_histogram.record(
                        row["duration_seconds"],
                        attributes=attributes
                    )

                if row["records_inserted"]:
                    self.ingestion_records_counter.add(
                        row["records_inserted"],
                        attributes={**attributes, "type": "inserted"}
                    )

                if row["records_skipped"]:
                    self.ingestion_records_counter.add(
                        row["records_skipped"],
                        attributes={**attributes, "type": "skipped"}
                    )

                logger.info(f"Exported ingestion health: {row['status']}")
        except sqlite3.OperationalError as e:
            logger.warning(f"Could not export ingestion health: {e}")

    def run(self):
        """Run the full export process"""
        start_time = time.time()
        logger.info("Starting AdGuard metrics + logs export to SigNoz")

        try:
            self.connect_db()

            # Export all metrics (existing)
            self.export_client_metrics()
            self.export_anomaly_metrics()
            self.export_blocked_domains(limit=20)
            self.export_ingestion_health()

            # NEW: Export anomaly logs
            self.export_anomaly_logs()

            # Wait for export to complete
            time.sleep(3)  # Increased to 3s for logs to flush

            duration = time.time() - start_time
            logger.info(f"Export completed successfully in {duration:.2f} seconds")

        except Exception as e:
            logger.error(f"Export failed: {e}", exc_info=True)
            raise

        finally:
            self.close_db()


def main():
    """Main entry point"""
    try:
        exporter = AdGuardMetricsExporter(DB_PATH, SIGNOZ_ENDPOINT)
        exporter.run()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        exit(1)


if __name__ == "__main__":
    main()
