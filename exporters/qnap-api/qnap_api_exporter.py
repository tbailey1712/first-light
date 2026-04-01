#!/usr/bin/env python3
"""
QNAP API Exporter for Prometheus

Queries QNAP NAS via API for detailed metrics:
- Per-disk SMART status and health
- Shared folder usage (QTS 5.x Storage Pool model)
- Container Station containers
- Network statistics
"""

import os
import time
import logging
import base64
import requests
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
from prometheus_client import start_http_server, Gauge, Info

# Disable SSL warnings for self-signed certs
requests.packages.urllib3.disable_warnings()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

QNAP_HOST = os.getenv('QNAP_HOST', 'nas.mcducklabs.com')
QNAP_USERNAME = os.getenv('QNAP_USERNAME', 'firstlight')
QNAP_PASSWORD = os.getenv('QNAP_PASSWORD', 'f1rstl1ght')
QNAP_PORT = int(os.getenv('QNAP_PORT', '443'))
QNAP_PROTOCOL = os.getenv('QNAP_PROTOCOL', 'https')
EXPORTER_PORT = int(os.getenv('EXPORTER_PORT', '9004'))
SCRAPE_INTERVAL = int(os.getenv('SCRAPE_INTERVAL', '60'))

# ── Prometheus metrics (ALL must be module-level — never instantiate inside a loop) ──

qnap_system_info = Info('qnap_system', 'QNAP system information')
qnap_uptime_seconds = Gauge('qnap_uptime_seconds', 'System uptime', ['host'])

# System resources
qnap_cpu_usage_percent = Gauge('qnap_cpu_usage_percent', 'CPU usage percentage', ['host'])
qnap_memory_total_bytes = Gauge('qnap_memory_total_bytes', 'Total memory bytes', ['host'])
qnap_memory_free_bytes = Gauge('qnap_memory_free_bytes', 'Free memory bytes', ['host'])
qnap_memory_used_bytes = Gauge('qnap_memory_used_bytes', 'Used memory bytes', ['host'])
qnap_cpu_temperature_celsius = Gauge('qnap_cpu_temperature_celsius', 'CPU temperature', ['host'])
qnap_system_temperature_celsius = Gauge('qnap_system_temperature_celsius', 'System temperature', ['host'])

# Disk metrics
qnap_disk_smart_status = Gauge('qnap_disk_smart_status', 'SMART status (1=good, 0=bad)', ['host', 'disk', 'model'])
qnap_disk_temperature_celsius = Gauge('qnap_disk_temperature_celsius', 'Disk temperature', ['host', 'disk', 'model'])
qnap_disk_capacity_bytes = Gauge('qnap_disk_capacity_bytes', 'Disk capacity', ['host', 'disk', 'model'])
qnap_disk_bad_sectors = Gauge('qnap_disk_bad_sectors', 'Bad sectors count', ['host', 'disk'])

# Shared folder / volume metrics
qnap_volume_capacity_bytes = Gauge('qnap_volume_capacity_bytes', 'Volume capacity', ['host', 'volume', 'pool'])
qnap_volume_used_bytes = Gauge('qnap_volume_used_bytes', 'Volume used space', ['host', 'volume', 'pool'])
qnap_volume_free_bytes = Gauge('qnap_volume_free_bytes', 'Volume free space', ['host', 'volume', 'pool'])

# Network metrics
qnap_network_rx_bytes = Gauge('qnap_network_rx_bytes_total', 'Network RX bytes', ['host', 'interface'])
qnap_network_tx_bytes = Gauge('qnap_network_tx_bytes_total', 'Network TX bytes', ['host', 'interface'])

# Container metrics
qnap_container_status = Gauge('qnap_container_status', 'Container status (1=running, 0=stopped)', ['host', 'container', 'image'])
qnap_container_cpu = Gauge('qnap_container_cpu_percent', 'Container CPU usage', ['host', 'container'])
qnap_container_memory = Gauge('qnap_container_memory_bytes', 'Container memory usage', ['host', 'container'])


def parse_value(value: Any, default: float = 0.0) -> float:
    """Parse a value from API response, handling various string formats."""
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        value = value.replace('%', '').replace(' ', '').strip()
        try:
            return float(value)
        except ValueError:
            return default
    return default


class QNAPAPIClient:
    """Client for QNAP NAS API."""

    def __init__(self, host: str, username: str, password: str, port: int = 443, protocol: str = 'https'):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.protocol = protocol
        self.base_url = f'{protocol}://{host}:{port}'
        self.sid = None

    def login(self) -> bool:
        """Authenticate and get session ID."""
        try:
            encoded_pwd = base64.b64encode(self.password.encode()).decode()
            response = requests.post(
                f'{self.base_url}/cgi-bin/authLogin.cgi',
                data={'user': self.username, 'pwd': encoded_pwd},
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                verify=False,
                timeout=10,
            )
            response.raise_for_status()
            root = ET.fromstring(response.content)
            auth_passed = root.find('.//authPassed')
            if auth_passed is not None and auth_passed.text == '1':
                auth_sid = root.find('.//authSid')
                if auth_sid is not None and auth_sid.text:
                    self.sid = auth_sid.text
                    logger.info(f"Authenticated to QNAP at {self.host}")
                    return True
            logger.error("QNAP authentication failed")
            return False
        except Exception as e:
            logger.error(f"Login error: {e}")
            return False

    def _xml_request(self, endpoint: str, params: Dict = None) -> Optional[Dict]:
        """GET endpoint, parse XML response into a dict."""
        if not self.sid and not self.login():
            return None
        try:
            p = dict(params or {})
            p['sid'] = self.sid
            response = requests.get(
                f'{self.base_url}{endpoint}', params=p, verify=False, timeout=30
            )
            if response.status_code == 200:
                try:
                    return self._xml_to_dict(ET.fromstring(response.content))
                except Exception:
                    return {'content': response.text}
            logger.error(f"Request failed: {endpoint} HTTP {response.status_code}")
            return None
        except Exception as e:
            logger.error(f"Request error: {e}")
            return None

    def _xml_to_dict(self, element: ET.Element) -> Dict:
        """Convert XML element to dict; multiple same-tag children become a list."""
        result = {}
        for child in element:
            child_data = self._xml_to_dict(child) if len(child) > 0 else child.text
            if child.tag in result:
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_data)
            else:
                result[child.tag] = child_data
        return result

    def get_system_info(self) -> Optional[Dict]:
        return self._xml_request('/cgi-bin/management/manaRequest.cgi', {
            'subfunc': 'sysinfo', 'hd': 'no', 'multicpu': 'yes'
        })

    def get_disk_info(self) -> Optional[Dict]:
        return self._xml_request('/cgi-bin/disk/disk_manage.cgi', {
            'func': 'extra_get', 'disktype': 'all', 'is_ajax': '1'
        })

    def get_share_list(self) -> Optional[list]:
        """
        Get per-shared-folder size info via the File Station API.

        Returns each share's name, used bytes, capacity (quota), and pool.
        This is the correct QTS 5.x API — chartReq.cgi returns underlying
        storage volume allocations which don't match what Storage Manager shows.
        """
        if not self.sid and not self.login():
            return None
        try:
            response = requests.get(
                f'{self.base_url}/cgi-bin/filemanager/utilRequest.cgi',
                params={
                    'func': 'get_share_list',
                    'sid': self.sid,
                    'is_iso': '0',
                },
                verify=False,
                timeout=30,
            )
            if response.status_code != 200:
                logger.warning(f"get_share_list: HTTP {response.status_code}")
                return None
            data = response.json()
            shares = data.get('shares', data.get('data', []))
            if not isinstance(shares, list):
                return None
            return shares
        except Exception as e:
            logger.warning(f"get_share_list failed: {e}")
            return None

    def get_containers(self) -> Optional[List]:
        """Get Container Station containers."""
        if not self.sid and not self.login():
            return None
        try:
            response = requests.get(
                f'{self.base_url}/container-station/api/v1/container',
                params={'sid': self.sid},
                verify=False,
                timeout=10,
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None


def collect_metrics(client: QNAPAPIClient, hostname: str):
    """Collect all metrics from QNAP and update Prometheus gauges."""
    logger.info("Collecting QNAP API metrics...")

    try:
        # ── System info ────────────────────────────────────────────────────────
        sys_info = client.get_system_info()
        if sys_info:
            root = sys_info.get('func', {}).get('ownContent', {}).get('root', {})
            if root:
                uptime_s = (
                    parse_value(root.get('uptime_day')) * 86400
                    + parse_value(root.get('uptime_hour')) * 3600
                    + parse_value(root.get('uptime_min')) * 60
                    + parse_value(root.get('uptime_sec'))
                )
                qnap_uptime_seconds.labels(host=hostname).set(uptime_s)

                cpu = parse_value(root.get('cpu_usage'))
                if cpu > 0:
                    qnap_cpu_usage_percent.labels(host=hostname).set(cpu)

                total_mem_mb = parse_value(root.get('total_memory'))
                free_mem_mb = parse_value(root.get('free_memory'))
                if total_mem_mb > 0:
                    total_b = total_mem_mb * 1024 * 1024
                    free_b = free_mem_mb * 1024 * 1024
                    qnap_memory_total_bytes.labels(host=hostname).set(total_b)
                    qnap_memory_free_bytes.labels(host=hostname).set(free_b)
                    qnap_memory_used_bytes.labels(host=hostname).set(total_b - free_b)

                cpu_temp = parse_value(root.get('cpu_tempc'))
                if cpu_temp > 0:
                    qnap_cpu_temperature_celsius.labels(host=hostname).set(cpu_temp)

                sys_temp = parse_value(root.get('sys_tempc'))
                if sys_temp > 0:
                    qnap_system_temperature_celsius.labels(host=hostname).set(sys_temp)

                for i in range(1, 10):
                    if f'eth_status{i}' not in root:
                        break
                    ifname = root.get(f'ifname{i}', f'eth{i-1}')
                    rx = parse_value(root.get(f'rx_packet{i}'))
                    tx = parse_value(root.get(f'tx_packet{i}'))
                    if rx > 0 or tx > 0:
                        qnap_network_rx_bytes.labels(host=hostname, interface=ifname).set(rx)
                        qnap_network_tx_bytes.labels(host=hostname, interface=ifname).set(tx)

        # ── Shared folder usage (QTS 5.x Storage Manager model) ───────────────
        shares = client.get_share_list()
        if shares:
            logger.info(f"Found {len(shares)} shared folders via File Station API")
            for share in shares:
                name = share.get('filename') or share.get('name') or share.get('sharename', 'unknown')
                pool = share.get('vol_no') or share.get('pool_name') or 'unknown'

                # Used bytes — field names vary by firmware version
                used_bytes = parse_value(
                    share.get('vol_size_bytes')
                    or share.get('used_size')
                    or share.get('size_used')
                )
                # Quota/capacity: 0 means unlimited (no quota set)
                quota_bytes = parse_value(
                    share.get('vol_quota_bytes')
                    or share.get('quota')
                    or share.get('capacity')
                )
                free_bytes = quota_bytes - used_bytes if quota_bytes > 0 else 0

                if used_bytes > 0:
                    qnap_volume_used_bytes.labels(host=hostname, volume=name, pool=pool).set(used_bytes)
                    if quota_bytes > 0:
                        qnap_volume_capacity_bytes.labels(host=hostname, volume=name, pool=pool).set(quota_bytes)
                        qnap_volume_free_bytes.labels(host=hostname, volume=name, pool=pool).set(free_bytes)
                        pct = used_bytes / quota_bytes * 100
                        logger.debug(f"Share {name}: {used_bytes/(1024**3):.1f}GB / {quota_bytes/(1024**3):.1f}GB ({pct:.1f}%)")
                    else:
                        logger.debug(f"Share {name}: {used_bytes/(1024**3):.1f}GB used (no quota)")
        else:
            logger.warning("get_share_list returned nothing — volume metrics not updated this cycle")

        # ── Container Station ──────────────────────────────────────────────────
        containers = client.get_containers()
        if containers and isinstance(containers, list):
            logger.info(f"Found {len(containers)} containers")
            for container in containers:
                name = container.get('name', 'unknown')
                image = container.get('image', 'unknown')
                state = container.get('state', 'unknown')
                qnap_container_status.labels(
                    host=hostname, container=name, image=image
                ).set(1 if state == 'running' else 0)
                stats = container.get('stats', {})
                if stats:
                    cpu = parse_value(stats.get('cpu_percent'))
                    mem = parse_value(stats.get('memory_usage'))
                    if cpu > 0:
                        qnap_container_cpu.labels(host=hostname, container=name).set(cpu)
                    if mem > 0:
                        qnap_container_memory.labels(host=hostname, container=name).set(mem)

        logger.info("Metrics collection completed")

    except Exception as e:
        logger.error(f"Error collecting metrics: {e}", exc_info=True)


def main():
    logger.info(f"Starting QNAP API exporter on port {EXPORTER_PORT}")
    logger.info(f"QNAP host: {QNAP_HOST}:{QNAP_PORT}, scrape interval: {SCRAPE_INTERVAL}s")

    start_http_server(EXPORTER_PORT)
    logger.info(f"Metrics available at http://0.0.0.0:{EXPORTER_PORT}/metrics")

    client = QNAPAPIClient(QNAP_HOST, QNAP_USERNAME, QNAP_PASSWORD, QNAP_PORT, QNAP_PROTOCOL)
    if not client.login():
        logger.error("Initial QNAP authentication failed — exiting")
        return

    while True:
        collect_metrics(client, QNAP_HOST)
        time.sleep(SCRAPE_INTERVAL)


if __name__ == '__main__':
    main()
