#!/usr/bin/env python3
"""
Device Inventory Discovery

Discovers and tracks network devices from multiple sources:
- UniFi Controller API
- DHCP leases (pfSense, AdGuard Home)
- Active network scanning (optional)

Maintains a SQLite database of all seen devices with:
- MAC address, IP address, hostname
- Manufacturer (from MAC OUI)
- Device type classification
- First seen / last seen timestamps
- VLAN / network location

Exposes Prometheus metrics for device counts and status.
"""

import os
import sys
import time
import logging
import sqlite3
import re
import requests
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import yaml
from prometheus_client import start_http_server, Gauge, Info, Counter

# Disable SSL warnings for self-signed certs
requests.packages.urllib3.disable_warnings()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Prometheus metrics
device_count = Gauge('network_devices_total', 'Total number of discovered devices', ['device_type', 'status'])
device_info = Info('network_device', 'Device information')
new_devices_counter = Counter('network_devices_new_total', 'Count of newly discovered devices')
device_last_seen = Gauge('network_device_last_seen_timestamp', 'Last seen timestamp', ['mac', 'hostname'])


@dataclass
class NetworkDevice:
    """Represents a network device."""
    mac: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    manufacturer: Optional[str] = None
    device_type: Optional[str] = None
    vlan: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    is_authorized: bool = True
    notes: Optional[str] = None


class DeviceInventory:
    """Device inventory database manager."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize SQLite database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                ip TEXT,
                hostname TEXT,
                manufacturer TEXT,
                device_type TEXT,
                vlan TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                is_authorized BOOLEAN DEFAULT 1,
                notes TEXT
            )
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_last_seen ON devices(last_seen)
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_device_type ON devices(device_type)
        ''')

        conn.commit()
        conn.close()
        logger.info(f"Device inventory database initialized at {self.db_path}")

    def upsert_device(self, device: NetworkDevice) -> bool:
        """Insert or update a device. Returns True if new device."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Check if device exists
        cursor.execute('SELECT mac, first_seen FROM devices WHERE mac = ?', (device.mac,))
        existing = cursor.fetchone()

        is_new = existing is None
        now = datetime.now()

        if is_new:
            # New device
            cursor.execute('''
                INSERT INTO devices (mac, ip, hostname, manufacturer, device_type, vlan,
                                     first_seen, last_seen, is_authorized, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                device.mac, device.ip, device.hostname, device.manufacturer,
                device.device_type, device.vlan, now, now, device.is_authorized, device.notes
            ))
            logger.info(f"New device discovered: {device.mac} ({device.hostname or 'unknown'}) - {device.ip}")
        else:
            # Update existing device
            cursor.execute('''
                UPDATE devices
                SET ip = ?, hostname = ?, manufacturer = ?, device_type = ?,
                    vlan = ?, last_seen = ?, notes = ?
                WHERE mac = ?
            ''', (
                device.ip, device.hostname, device.manufacturer, device.device_type,
                device.vlan, now, device.notes, device.mac
            ))

        conn.commit()
        conn.close()
        return is_new

    def get_all_devices(self) -> List[Dict]:
        """Get all devices from database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM devices ORDER BY last_seen DESC')
        devices = [dict(row) for row in cursor.fetchall()]

        conn.close()
        return devices

    def get_device_stats(self) -> Dict:
        """Get device statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        stats = {}

        # Total devices
        cursor.execute('SELECT COUNT(*) FROM devices')
        stats['total'] = cursor.fetchone()[0]

        # Devices by type
        cursor.execute('SELECT device_type, COUNT(*) FROM devices GROUP BY device_type')
        stats['by_type'] = dict(cursor.fetchall())

        # Active devices (seen in last 24 hours)
        day_ago = datetime.now() - timedelta(days=1)
        cursor.execute('SELECT COUNT(*) FROM devices WHERE last_seen > ?', (day_ago,))
        stats['active_24h'] = cursor.fetchone()[0]

        # Unauthorized devices
        cursor.execute('SELECT COUNT(*) FROM devices WHERE is_authorized = 0')
        stats['unauthorized'] = cursor.fetchone()[0]

        conn.close()
        return stats


class UniFiClient:
    """UniFi Controller API client."""

    def __init__(self, host: str, port: int, username: str, password: str, site: str = 'default', verify_ssl: bool = False):
        self.base_url = f"https://{host}:{port}"
        self.username = username
        self.password = password
        self.site = site
        self.verify = verify_ssl
        self.session = requests.Session()
        self.csrf_token = None

    def login(self) -> bool:
        """Authenticate to UniFi Controller."""
        try:
            url = f"{self.base_url}/api/login"
            data = {
                'username': self.username,
                'password': self.password
            }

            response = self.session.post(url, json=data, verify=self.verify, timeout=10)

            if response.status_code == 200:
                # Extract CSRF token if present
                if 'X-CSRF-Token' in response.headers:
                    self.csrf_token = response.headers['X-CSRF-Token']

                logger.info(f"Successfully authenticated to UniFi Controller at {self.base_url}")
                return True
            else:
                logger.error(f"UniFi login failed: HTTP {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"UniFi login error: {e}")
            return False

    def get_clients(self) -> List[Dict]:
        """Get all clients from UniFi Controller."""
        try:
            url = f"{self.base_url}/api/s/{self.site}/stat/sta"
            headers = {}
            if self.csrf_token:
                headers['X-CSRF-Token'] = self.csrf_token

            response = self.session.get(url, headers=headers, verify=self.verify, timeout=30)

            if response.status_code == 200:
                data = response.json()
                clients = data.get('data', [])
                logger.info(f"Retrieved {len(clients)} clients from UniFi")
                return clients
            else:
                logger.error(f"Failed to get UniFi clients: HTTP {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Error getting UniFi clients: {e}")
            return []


def classify_device(hostname: Optional[str], manufacturer: Optional[str], rules: Dict) -> str:
    """Classify device type based on hostname and manufacturer."""
    # Try hostname patterns first
    if hostname:
        for pattern, device_type in rules.get('hostname_rules', {}).items():
            if re.search(pattern, hostname, re.IGNORECASE):
                return device_type

    # Try manufacturer patterns
    if manufacturer:
        for mfr_pattern, device_type in rules.get('manufacturer_rules', {}).items():
            if mfr_pattern.lower() in manufacturer.lower():
                return device_type

    return 'unknown'


def discover_devices(config: Dict, inventory: DeviceInventory):
    """Main discovery loop."""
    logger.info("Starting device discovery...")

    classification_rules = config.get('classification', {})
    new_device_count = 0

    # Discover from UniFi
    if config.get('unifi', {}).get('enabled', False):
        unifi_config = config['unifi']
        client = UniFiClient(
            host=unifi_config['host'],
            port=unifi_config['port'],
            username=unifi_config['username'],
            password=unifi_config['password'],
            site=unifi_config.get('site', 'default'),
            verify_ssl=unifi_config.get('verify_ssl', False)
        )

        if client.login():
            clients = client.get_clients()
            for client_data in clients:
                mac = client_data.get('mac', '').lower()
                if not mac:
                    continue

                device = NetworkDevice(
                    mac=mac,
                    ip=client_data.get('ip'),
                    hostname=client_data.get('hostname') or client_data.get('name'),
                    manufacturer=client_data.get('oui'),
                    vlan=str(client_data.get('vlan')) if client_data.get('vlan') else None,
                )

                # Classify device
                device.device_type = classify_device(
                    device.hostname,
                    device.manufacturer,
                    classification_rules
                )

                if inventory.upsert_device(device):
                    new_device_count += 1
                    new_devices_counter.inc()

    logger.info(f"Discovery complete. Found {new_device_count} new devices.")
    update_metrics(inventory)


def update_metrics(inventory: DeviceInventory):
    """Update Prometheus metrics from inventory."""
    stats = inventory.get_device_stats()

    # Update device counts by type
    device_count._metrics.clear()
    for device_type, count in stats.get('by_type', {}).items():
        device_type = device_type or 'unknown'
        device_count.labels(device_type=device_type, status='total').set(count)

    # Update active device count
    device_count.labels(device_type='all', status='active_24h').set(stats.get('active_24h', 0))

    # Update unauthorized count
    device_count.labels(device_type='all', status='unauthorized').set(stats.get('unauthorized', 0))

    logger.debug(f"Metrics updated: {stats}")


def main():
    """Main entry point."""
    # Load configuration
    config_path = os.getenv('CONFIG_PATH', '/app/config.yaml')

    if not os.path.exists(config_path):
        logger.error(f"Config file not found: {config_path}")
        logger.info("Please copy config.yaml.example to config.yaml and configure it")
        sys.exit(1)

    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    # Initialize database
    db_path = config.get('database', {}).get('path', '/data/device_inventory.db')
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    inventory = DeviceInventory(db_path)

    # Start Prometheus metrics server
    metrics_config = config.get('metrics', {})
    if metrics_config.get('enabled', True):
        metrics_port = metrics_config.get('port', 9005)
        start_http_server(metrics_port)
        logger.info(f"Prometheus metrics available at http://0.0.0.0:{metrics_port}/metrics")

    # Discovery loop
    interval = config.get('discovery', {}).get('interval', 300)

    while True:
        try:
            discover_devices(config, inventory)
        except Exception as e:
            logger.error(f"Discovery error: {e}", exc_info=True)

        logger.info(f"Sleeping for {interval} seconds...")
        time.sleep(interval)


if __name__ == '__main__':
    main()
