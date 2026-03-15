#!/usr/bin/env python3
"""
QNAP API Exporter for Prometheus

Queries QNAP NAS via API for detailed metrics:
- Per-disk SMART status and health
- Volume/share usage details
- Container Station containers
- RAID status
- Network statistics
- Active connections
"""

import os
import time
import logging
import re
import base64
import requests
from typing import Dict, List, Any, Optional
from urllib.parse import urlencode
import xml.etree.ElementTree as ET
from prometheus_client import start_http_server, Gauge, Info

# Disable SSL warnings for self-signed certs
requests.packages.urllib3.disable_warnings()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Environment variables
QNAP_HOST = os.getenv('QNAP_HOST', 'nas.mcducklabs.com')
QNAP_USERNAME = os.getenv('QNAP_USERNAME', 'firstlight')
QNAP_PASSWORD = os.getenv('QNAP_PASSWORD', 'f1rstl1ght')
QNAP_PORT = int(os.getenv('QNAP_PORT', '443'))
QNAP_PROTOCOL = os.getenv('QNAP_PROTOCOL', 'https')
EXPORTER_PORT = int(os.getenv('EXPORTER_PORT', '9004'))
SCRAPE_INTERVAL = int(os.getenv('SCRAPE_INTERVAL', '60'))

# Prometheus metrics
qnap_system_info = Info('qnap_system', 'QNAP system information')
qnap_uptime_seconds = Gauge('qnap_uptime_seconds', 'System uptime', ['host'])

# Disk metrics
qnap_disk_smart_status = Gauge('qnap_disk_smart_status', 'SMART status (1=good, 0=bad)', ['host', 'disk', 'model'])
qnap_disk_temp = Gauge('qnap_disk_temperature_celsius', 'Disk temperature', ['host', 'disk', 'model'])
qnap_disk_capacity = Gauge('qnap_disk_capacity_bytes', 'Disk capacity', ['host', 'disk', 'model'])
qnap_disk_bad_sectors = Gauge('qnap_disk_bad_sectors', 'Bad sectors count', ['host', 'disk'])

# Volume metrics
qnap_volume_capacity = Gauge('qnap_volume_capacity_bytes', 'Volume capacity', ['host', 'volume', 'pool'])
qnap_volume_used = Gauge('qnap_volume_used_bytes', 'Volume used space', ['host', 'volume', 'pool'])
qnap_volume_free = Gauge('qnap_volume_free_bytes', 'Volume free space', ['host', 'volume', 'pool'])

# RAID metrics
qnap_raid_status = Gauge('qnap_raid_status', 'RAID status (1=healthy, 0=degraded)', ['host', 'raid_id', 'type'])

# Network metrics
qnap_network_rx_bytes = Gauge('qnap_network_rx_bytes_total', 'Network RX bytes', ['host', 'interface'])
qnap_network_tx_bytes = Gauge('qnap_network_tx_bytes_total', 'Network TX bytes', ['host', 'interface'])

# Container metrics
qnap_container_status = Gauge('qnap_container_status', 'Container status (1=running, 0=stopped)', ['host', 'container', 'image'])
qnap_container_cpu = Gauge('qnap_container_cpu_percent', 'Container CPU usage', ['host', 'container'])
qnap_container_memory = Gauge('qnap_container_memory_bytes', 'Container memory usage', ['host', 'container'])


class QNAPAPIClient:
    """Client for QNAP API."""

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
            url = f'{self.base_url}/cgi-bin/authLogin.cgi'

            # QNAP API requires base64-encoded password
            encoded_pwd = base64.b64encode(self.password.encode()).decode()

            # Use POST with form data
            data = {
                'user': self.username,
                'pwd': encoded_pwd
            }
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            response = requests.post(url, data=data, headers=headers, verify=False, timeout=10)

            if response.status_code == 200:
                # Parse XML response
                root = ET.fromstring(response.content)

                # Check if authentication passed
                auth_passed = root.find('.//authPassed')
                if auth_passed is not None and auth_passed.text == '1':
                    # Extract session ID
                    auth_sid = root.find('.//authSid')
                    if auth_sid is not None and auth_sid.text:
                        self.sid = auth_sid.text
                        logger.info(f"Successfully authenticated to QNAP at {self.host}")
                        return True
                    else:
                        logger.error("No session ID in response")
                        return False
                else:
                    logger.error("Authentication failed - authPassed != 1")
                    return False
            else:
                logger.error(f"Login failed: HTTP {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Login error: {e}")
            return False

    def _request(self, endpoint: str, params: Dict = None) -> Optional[Dict]:
        """Make authenticated API request."""
        if not self.sid:
            if not self.login():
                return None

        try:
            url = f'{self.base_url}{endpoint}'
            if params is None:
                params = {}
            params['sid'] = self.sid

            response = requests.get(url, params=params, verify=False, timeout=30)

            if response.status_code == 200:
                # Try to parse as XML
                try:
                    root = ET.fromstring(response.content)
                    return self._xml_to_dict(root)
                except:
                    # If not XML, return text
                    return {'content': response.text}
            else:
                logger.error(f"Request failed: {endpoint} - HTTP {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Request error: {e}")
            return None

    def _xml_to_dict(self, element: ET.Element) -> Dict:
        """Convert XML element to dictionary."""
        result = {}
        for child in element:
            if len(child) > 0:
                result[child.tag] = self._xml_to_dict(child)
            else:
                result[child.tag] = child.text
        return result

    def get_system_info(self) -> Optional[Dict]:
        """Get system information."""
        return self._request('/cgi-bin/management/manaRequest.cgi', {
            'subfunc': 'sysinfo',
            'hd': 'no',
            'multicpu': 'yes'
        })

    def get_disk_info(self) -> Optional[Dict]:
        """Get disk information and SMART status."""
        return self._request('/cgi-bin/disk/disk_manage.cgi', {
            'func': 'extra_get',
            'disktype': 'all',
            'is_ajax': '1'
        })

    def get_volume_info(self) -> Optional[Dict]:
        """Get volume/pool information."""
        return self._request('/cgi-bin/disk/disk_manage.cgi', {
            'store': 'poolInfo',
            'func': 'vol_info',
            'Pool': 'all'
        })

    def get_containers(self) -> Optional[List]:
        """Get Container Station containers."""
        try:
            url = f'{self.base_url}/container-station/api/v1/container'
            response = requests.get(
                url,
                params={'sid': self.sid},
                verify=False,
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return None
        except:
            return None


def parse_value(value: Any, default: float = 0.0) -> float:
    """Parse a value from API response, handling CDATA and various formats."""
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        # Remove % sign if present
        value = value.replace('%', '').replace(' ', '').strip()
        try:
            return float(value)
        except ValueError:
            return default
    return default


def collect_metrics(client: QNAPAPIClient, hostname: str):
    """Collect all metrics from QNAP."""
    logger.info("Collecting QNAP API metrics...")

    try:
        # System info
        sys_info = client.get_system_info()
        if sys_info:
            # Navigate through the nested dict structure
            func = sys_info.get('func', {})
            own_content = func.get('ownContent', {})
            root = own_content.get('root', {})

            if root:
                # Parse uptime
                uptime_day = parse_value(root.get('uptime_day'))
                uptime_hour = parse_value(root.get('uptime_hour'))
                uptime_min = parse_value(root.get('uptime_min'))
                uptime_sec = parse_value(root.get('uptime_sec'))

                total_uptime_seconds = (uptime_day * 86400) + (uptime_hour * 3600) + (uptime_min * 60) + uptime_sec
                qnap_uptime_seconds.labels(host=hostname).set(total_uptime_seconds)
                logger.debug(f"Uptime: {total_uptime_seconds} seconds ({uptime_day}d {uptime_hour}h {uptime_min}m)")

                # CPU usage
                cpu_usage = parse_value(root.get('cpu_usage'))
                if cpu_usage > 0:
                    # Create a CPU usage metric (not in original spec, but useful)
                    cpu_gauge = Gauge('qnap_cpu_usage_percent', 'CPU usage percentage', ['host'])
                    cpu_gauge.labels(host=hostname).set(cpu_usage)
                    logger.debug(f"CPU usage: {cpu_usage}%")

                # Memory
                total_memory = parse_value(root.get('total_memory'))
                free_memory = parse_value(root.get('free_memory'))
                if total_memory > 0:
                    # Convert MB to bytes
                    mem_total_gauge = Gauge('qnap_memory_total_bytes', 'Total memory', ['host'])
                    mem_free_gauge = Gauge('qnap_memory_free_bytes', 'Free memory', ['host'])
                    mem_used_gauge = Gauge('qnap_memory_used_bytes', 'Used memory', ['host'])

                    total_bytes = total_memory * 1024 * 1024
                    free_bytes = free_memory * 1024 * 1024
                    used_bytes = total_bytes - free_bytes

                    mem_total_gauge.labels(host=hostname).set(total_bytes)
                    mem_free_gauge.labels(host=hostname).set(free_bytes)
                    mem_used_gauge.labels(host=hostname).set(used_bytes)
                    logger.debug(f"Memory: {used_bytes / (1024**3):.1f}GB / {total_bytes / (1024**3):.1f}GB used")

                # Temperatures
                cpu_temp = parse_value(root.get('cpu_tempc'))
                sys_temp = parse_value(root.get('sys_tempc'))

                if cpu_temp > 0:
                    cpu_temp_gauge = Gauge('qnap_cpu_temperature_celsius', 'CPU temperature', ['host'])
                    cpu_temp_gauge.labels(host=hostname).set(cpu_temp)
                    logger.debug(f"CPU temp: {cpu_temp}°C")

                if sys_temp > 0:
                    sys_temp_gauge = Gauge('qnap_system_temperature_celsius', 'System temperature', ['host'])
                    sys_temp_gauge.labels(host=hostname).set(sys_temp)
                    logger.debug(f"System temp: {sys_temp}°C")

                # Network interfaces
                for i in range(1, 10):  # Support up to 9 interfaces
                    eth_status_key = f'eth_status{i}'
                    if eth_status_key not in root:
                        break

                    ifname = root.get(f'ifname{i}', f'eth{i-1}')
                    eth_status = parse_value(root.get(eth_status_key))
                    rx_packets = parse_value(root.get(f'rx_packet{i}'))
                    tx_packets = parse_value(root.get(f'tx_packet{i}'))

                    if rx_packets > 0 or tx_packets > 0:
                        qnap_network_rx_bytes.labels(host=hostname, interface=ifname).set(rx_packets)
                        qnap_network_tx_bytes.labels(host=hostname, interface=ifname).set(tx_packets)
                        logger.debug(f"Interface {ifname}: RX={rx_packets}, TX={tx_packets}")

        # Disk info
        disk_info = client.get_disk_info()
        if disk_info:
            logger.debug(f"Disk info response: {list(disk_info.keys())[:5]}")
            # QNAP disk API structure varies - log for debugging
            # Will implement once we see actual structure

        # Volume info
        vol_info = client.get_volume_info()
        if vol_info:
            logger.debug(f"Volume info response: {list(vol_info.keys())[:5]}")
            # QNAP volume API structure varies - log for debugging
            # Will implement once we see actual structure

        # Container Station
        containers = client.get_containers()
        if containers and isinstance(containers, list):
            logger.info(f"Found {len(containers)} containers")
            for container in containers:
                name = container.get('name', 'unknown')
                image = container.get('image', 'unknown')
                state = container.get('state', 'unknown')

                status = 1 if state == 'running' else 0
                qnap_container_status.labels(
                    host=hostname,
                    container=name,
                    image=image
                ).set(status)

                # CPU and memory if available
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
    """Main exporter loop."""
    logger.info(f"Starting QNAP API exporter on port {EXPORTER_PORT}")
    logger.info(f"QNAP host: {QNAP_HOST}:{QNAP_PORT}")
    logger.info(f"Username: {QNAP_USERNAME}")
    logger.info(f"Scrape interval: {SCRAPE_INTERVAL}s")

    # Start Prometheus metrics server
    start_http_server(EXPORTER_PORT)
    logger.info(f"Metrics endpoint available at http://0.0.0.0:{EXPORTER_PORT}/metrics")

    # Create QNAP API client
    client = QNAPAPIClient(QNAP_HOST, QNAP_USERNAME, QNAP_PASSWORD, QNAP_PORT, QNAP_PROTOCOL)

    # Initial login
    if not client.login():
        logger.error("Failed to authenticate to QNAP. Exiting.")
        return

    # Collection loop
    while True:
        collect_metrics(client, QNAP_HOST)
        time.sleep(SCRAPE_INTERVAL)


if __name__ == '__main__':
    main()
