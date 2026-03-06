"""
Database schema and utilities for threat assessment reports.

Stores historical metrics for trend analysis.
"""

import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import json
import os


class ReportsDatabase:
    """Manages SQLite database for report metrics and trends."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            # Use environment variable or default to project dir
            reports_base = os.getenv("FIRST_LIGHT_REPORTS_DIR",
                                    str(Path(__file__).parent.parent.parent / "reports"))
            db_path = str(Path(reports_base) / "metrics" / "reports.db")
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
    
    def _init_schema(self):
        """Create database tables if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                -- Daily metrics table
                CREATE TABLE IF NOT EXISTS daily_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id TEXT UNIQUE NOT NULL,
                    date DATE NOT NULL,
                    firewall_blocks INTEGER,
                    dns_blocks INTEGER,
                    dns_high_risk_blocks INTEGER,
                    flow_alerts_critical INTEGER,
                    flow_alerts_warning INTEGER,
                    ssh_failures INTEGER,
                    unique_attacker_ips INTEGER,
                    disk_usage_percent REAL,
                    disk_used_gb REAL,
                    peak_bandwidth_mbps REAL,
                    interface_errors INTEGER,
                    container_restarts INTEGER,
                    service_uptime_hours REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE INDEX IF NOT EXISTS idx_daily_date ON daily_metrics(date);
                
                -- Security events table
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP,
                    event_type TEXT,
                    source_ip TEXT,
                    target TEXT,
                    action_taken TEXT,
                    severity TEXT,
                    report_id TEXT,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type);
                CREATE INDEX IF NOT EXISTS idx_events_source ON security_events(source_ip);
                
                -- Threat intelligence table
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    total_attempts INTEGER,
                    threat_type TEXT,
                    status TEXT,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE INDEX IF NOT EXISTS idx_threat_ip ON threat_intelligence(ip_address);
                CREATE INDEX IF NOT EXISTS idx_threat_status ON threat_intelligence(status);
            """)
    
    def save_daily_metrics(self, report_id: str, date: str, metrics: Dict[str, Any]):
        """Save daily metrics to database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO daily_metrics (
                    report_id, date, firewall_blocks, dns_blocks, dns_high_risk_blocks,
                    flow_alerts_critical, flow_alerts_warning, ssh_failures,
                    unique_attacker_ips, disk_usage_percent, disk_used_gb,
                    peak_bandwidth_mbps, interface_errors, container_restarts,
                    service_uptime_hours
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report_id,
                date,
                metrics.get('firewall_blocks', 0),
                metrics.get('dns_blocks', 0),
                metrics.get('dns_high_risk_blocks', 0),
                metrics.get('flow_alerts_critical', 0),
                metrics.get('flow_alerts_warning', 0),
                metrics.get('ssh_failures', 0),
                metrics.get('unique_attacker_ips', 0),
                metrics.get('disk_usage_percent', 0.0),
                metrics.get('disk_used_gb', 0.0),
                metrics.get('peak_bandwidth_mbps', 0.0),
                metrics.get('interface_errors', 0),
                metrics.get('container_restarts', 0),
                metrics.get('service_uptime_hours', 0.0),
            ))
            conn.commit()
    
    def save_security_event(self, event: Dict[str, Any], report_id: str):
        """Save a security event to database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO security_events (
                    timestamp, event_type, source_ip, target,
                    action_taken, severity, report_id, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.get('timestamp'),
                event.get('type'),
                event.get('source_ip'),
                event.get('target'),
                event.get('action_taken'),
                event.get('severity'),
                report_id,
                json.dumps(event.get('details', {})),
            ))
            conn.commit()
    
    def update_threat_intelligence(self, ip: str, threat_type: str, attempts: int):
        """Update or insert threat intelligence for an IP."""
        now = datetime.utcnow().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            # Check if IP exists
            cursor = conn.execute(
                "SELECT id, total_attempts FROM threat_intelligence WHERE ip_address = ?",
                (ip,)
            )
            row = cursor.fetchone()
            
            if row:
                # Update existing
                conn.execute("""
                    UPDATE threat_intelligence
                    SET last_seen = ?, total_attempts = total_attempts + ?,
                        threat_type = ?, updated_at = ?
                    WHERE ip_address = ?
                """, (now, attempts, threat_type, now, ip))
            else:
                # Insert new
                conn.execute("""
                    INSERT INTO threat_intelligence (
                        ip_address, first_seen, last_seen, total_attempts,
                        threat_type, status
                    ) VALUES (?, ?, ?, ?, ?, 'active')
                """, (ip, now, now, attempts, threat_type))
            
            conn.commit()
    
    def get_7day_average(self, metric: str) -> Optional[float]:
        """Get 7-day average for a metric."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(f"""
                SELECT AVG({metric})
                FROM daily_metrics
                WHERE date >= date('now', '-7 days')
            """)
            result = cursor.fetchone()
            return result[0] if result and result[0] is not None else None
    
    def get_previous_day_metric(self, metric: str) -> Optional[float]:
        """Get previous day's value for a metric."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(f"""
                SELECT {metric}
                FROM daily_metrics
                WHERE date = date('now', '-1 day')
            """)
            result = cursor.fetchone()
            return result[0] if result and result[0] is not None else None
