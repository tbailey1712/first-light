#!/usr/bin/env python3
"""
QNAP NAS SNMP Exporter for Prometheus

Queries QNAP NAS via SNMP and exposes metrics for:
- CPU usage
- Memory usage
- Disk temperatures and status
- Volume/pool usage
- Network interface traffic
- System uptime
"""

import os
import time
import logging
import re
from typing import Dict, List, Any, Optional
from pysnmp.hlapi import (
    getCmd, nextCmd, SnmpEngine, CommunityData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity
)
from prometheus_client import start_http_server, Gauge, Counter, Info

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Environment variables
QNAP_HOST = os.getenv('QNAP_HOST', 'nas.mcducklabs.com')
SNMP_COMMUNITY = os.getenv('SNMP_COMMUNITY', 'public')
SNMP_PORT = int(os.getenv('SNMP_PORT', '161'))
EXPORTER_PORT = int(os.getenv('EXPORTER_PORT', '9003'))
SCRAPE_INTERVAL = int(os.getenv('SCRAPE_INTERVAL', '60'))

# QNAP SNMP OIDs
QNAP_OID_BASE = '1.3.6.1.4.1.24681'
QNAP_CPU_USAGE = f'{QNAP_OID_BASE}.1.2.1.0'  # CPU usage percentage
QNAP_SYSTEM_TEMP = f'{QNAP_OID_BASE}.1.2.5.0'  # System temperature
QNAP_DISK_TABLE = f'{QNAP_OID_BASE}.1.2.11'  # Disk table
QNAP_VOLUME_TABLE = f'{QNAP_OID_BASE}.1.2.17'  # Volume table
QNAP_IF_TABLE = f'{QNAP_OID_BASE}.1.2.9'  # Network interface table

# Standard MIBs
HOST_RESOURCES_MIB = '1.3.6.1.2.1.25'
HR_STORAGE = f'{HOST_RESOURCES_MIB}.2.3.1'  # hrStorageTable
HR_SYSTEM_UPTIME = f'{HOST_RESOURCES_MIB}.1.1.0'  # hrSystemUptime

# Prometheus metrics
qnap_cpu_usage = Gauge('qnap_cpu_usage_percent', 'CPU usage percentage', ['host'])
qnap_system_temp = Gauge('qnap_system_temp_celsius', 'System temperature in Celsius', ['host'])
qnap_uptime_seconds = Gauge('qnap_uptime_seconds', 'System uptime', ['host'])

qnap_disk_temp = Gauge('qnap_disk_temp_celsius', 'Disk temperature', ['host', 'disk'])
qnap_disk_status = Gauge('qnap_disk_status', 'Disk status (1=good, 0=error)', ['host', 'disk'])

qnap_volume_size = Gauge('qnap_volume_size_bytes', 'Volume total size', ['host', 'volume'])
qnap_volume_used = Gauge('qnap_volume_used_bytes', 'Volume used space', ['host', 'volume'])
qnap_volume_free = Gauge('qnap_volume_free_bytes', 'Volume free space', ['host', 'volume'])

qnap_if_rx_bytes = Counter('qnap_interface_rx_bytes_total', 'Interface RX bytes', ['host', 'interface'])
qnap_if_tx_bytes = Counter('qnap_interface_tx_bytes_total', 'Interface TX bytes', ['host', 'interface'])

qnap_memory_total = Gauge('qnap_memory_total_bytes', 'Total memory', ['host'])
qnap_memory_used = Gauge('qnap_memory_used_bytes', 'Used memory', ['host'])


class QNAPSNMPClient:
    """SNMP client for QNAP NAS."""

    def __init__(self, host: str, community: str, port: int = 161):
        self.host = host
        self.community = community
        self.port = port

    def get(self, oid: str) -> Optional[str]:
        """Get single SNMP value."""
        try:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(self.community),
                UdpTransportTarget((self.host, self.port), timeout=5, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )

            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

            if errorIndication:
                logger.error(f"SNMP error: {errorIndication}")
                return None
            elif errorStatus:
                logger.error(f"SNMP error: {errorStatus.prettyPrint()}")
                return None
            else:
                for varBind in varBinds:
                    return str(varBind[1])
        except Exception as e:
            logger.error(f"Error querying {oid}: {e}")
            return None

    def walk(self, oid: str) -> List[tuple]:
        """Walk SNMP tree."""
        results = []
        try:
            for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(self.community),
                UdpTransportTarget((self.host, self.port), timeout=5, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False
            ):
                if errorIndication:
                    logger.error(f"SNMP walk error: {errorIndication}")
                    break
                elif errorStatus:
                    logger.error(f"SNMP walk error: {errorStatus.prettyPrint()}")
                    break
                else:
                    for varBind in varBinds:
                        results.append((str(varBind[0]), str(varBind[1])))
        except Exception as e:
            logger.error(f"Error walking {oid}: {e}")
        return results


def parse_temperature(temp_str: str) -> Optional[float]:
    """Parse QNAP temperature string like '45 C/113 F' to celsius."""
    match = re.search(r'(\d+)\s*C', temp_str)
    return float(match.group(1)) if match else None


def parse_percentage(pct_str: str) -> Optional[float]:
    """Parse percentage string like '50.7 %' to float."""
    match = re.search(r'([\d.]+)\s*%', pct_str)
    return float(match.group(1)) if match else None


def collect_metrics(client: QNAPSNMPClient, hostname: str):
    """Collect all metrics from QNAP."""
    logger.info("Collecting QNAP metrics...")

    try:
        # CPU usage
        cpu = client.get(QNAP_CPU_USAGE)
        if cpu:
            cpu_val = parse_percentage(cpu)
            if cpu_val is not None:
                qnap_cpu_usage.labels(host=hostname).set(cpu_val)
                logger.debug(f"CPU: {cpu_val}%")

        # System temperature
        sys_temp = client.get(QNAP_SYSTEM_TEMP)
        if sys_temp:
            temp_val = parse_temperature(sys_temp)
            if temp_val is not None:
                qnap_system_temp.labels(host=hostname).set(temp_val)
                logger.debug(f"System temp: {temp_val}°C")

        # System uptime (in timeticks, convert to seconds)
        uptime = client.get(HR_SYSTEM_UPTIME)
        if uptime:
            try:
                # Timeticks are in hundredths of a second
                uptime_val = int(uptime) / 100
                qnap_uptime_seconds.labels(host=hostname).set(uptime_val)
            except ValueError:
                pass

        # Disk information
        disk_table = client.walk(QNAP_DISK_TABLE)
        disk_data = {}
        for oid, value in disk_table:
            # Parse OID to get disk index and field
            # Format: 1.3.6.1.4.1.24681.1.2.11.1.{field}.{index}
            parts = oid.split('.')
            if len(parts) >= 2:
                field = parts[-2]
                index = parts[-1]

                if index not in disk_data:
                    disk_data[index] = {}

                if field == '2':  # Disk name
                    disk_data[index]['name'] = value
                elif field == '3':  # Disk temperature
                    temp = parse_temperature(value)
                    if temp:
                        disk_data[index]['temp'] = temp
                elif field == '4':  # Disk status
                    # QNAP status: GOOD, ERROR, WARNING, --
                    status = 1 if 'GOOD' in value.upper() else 0
                    disk_data[index]['status'] = status

        # Export disk metrics
        for index, data in disk_data.items():
            disk_name = data.get('name', f'disk{index}')
            if 'temp' in data:
                qnap_disk_temp.labels(host=hostname, disk=disk_name).set(data['temp'])
            if 'status' in data:
                qnap_disk_status.labels(host=hostname, disk=disk_name).set(data['status'])

        # Volume information
        volume_table = client.walk(QNAP_VOLUME_TABLE)
        volume_data = {}
        for oid, value in volume_table:
            parts = oid.split('.')
            if len(parts) >= 2:
                field = parts[-2]
                index = parts[-1]

                if index not in volume_data:
                    volume_data[index] = {}

                if field == '2':  # Volume name
                    volume_data[index]['name'] = value
                elif field == '4':  # Volume size (might be in KB or GB, need to check)
                    try:
                        # Parse size string, handle different formats
                        size_match = re.search(r'([\d.]+)\s*(GB|TB|MB)', value)
                        if size_match:
                            size_val = float(size_match.group(1))
                            unit = size_match.group(2)
                            multiplier = {'MB': 1024**2, 'GB': 1024**3, 'TB': 1024**4}
                            volume_data[index]['size'] = size_val * multiplier.get(unit, 1)
                    except:
                        pass
                elif field == '5':  # Volume free space
                    try:
                        size_match = re.search(r'([\d.]+)\s*(GB|TB|MB)', value)
                        if size_match:
                            size_val = float(size_match.group(1))
                            unit = size_match.group(2)
                            multiplier = {'MB': 1024**2, 'GB': 1024**3, 'TB': 1024**4}
                            volume_data[index]['free'] = size_val * multiplier.get(unit, 1)
                    except:
                        pass

        # Export volume metrics
        for index, data in volume_data.items():
            vol_name = data.get('name', f'volume{index}')
            if 'size' in data:
                qnap_volume_size.labels(host=hostname, volume=vol_name).set(data['size'])
            if 'free' in data:
                qnap_volume_free.labels(host=hostname, volume=vol_name).set(data['free'])
                if 'size' in data:
                    used = data['size'] - data['free']
                    qnap_volume_used.labels(host=hostname, volume=vol_name).set(used)

        # Network interface stats
        if_table = client.walk(QNAP_IF_TABLE)
        if_data = {}
        for oid, value in if_table:
            parts = oid.split('.')
            if len(parts) >= 2:
                field = parts[-2]
                index = parts[-1]

                if index not in if_data:
                    if_data[index] = {}

                if field == '2':  # Interface name
                    if_data[index]['name'] = value
                elif field == '3':  # RX bytes
                    try:
                        if_data[index]['rx'] = int(value)
                    except:
                        pass
                elif field == '4':  # TX bytes
                    try:
                        if_data[index]['tx'] = int(value)
                    except:
                        pass

        # Export interface metrics
        for index, data in if_data.items():
            if_name = data.get('name', f'eth{index}')
            if 'rx' in data:
                qnap_if_rx_bytes.labels(host=hostname, interface=if_name).inc(data['rx'])
            if 'tx' in data:
                qnap_if_tx_bytes.labels(host=hostname, interface=if_name).inc(data['tx'])

        # Memory information from hrStorageTable
        storage_table = client.walk(HR_STORAGE)
        for oid, value in storage_table:
            # Look for "Physical memory" entry
            if 'Physical memory' in value or '.2.1' in oid:  # hrStorageDescr
                # Get the index
                index = oid.split('.')[-1]
                # Get size and used
                size_oid = f'{HR_STORAGE}.5.{index}'  # hrStorageSize
                used_oid = f'{HR_STORAGE}.6.{index}'  # hrStorageUsed
                units_oid = f'{HR_STORAGE}.4.{index}'  # hrStorageAllocationUnits

                size = client.get(size_oid)
                used = client.get(used_oid)
                units = client.get(units_oid)

                if size and used and units:
                    try:
                        unit_bytes = int(units.split()[-1]) if 'Bytes' in units else 1024
                        total_bytes = int(size) * unit_bytes
                        used_bytes = int(used) * unit_bytes
                        qnap_memory_total.labels(host=hostname).set(total_bytes)
                        qnap_memory_used.labels(host=hostname).set(used_bytes)
                    except:
                        pass
                break

        logger.info("Metrics collection completed")

    except Exception as e:
        logger.error(f"Error collecting metrics: {e}", exc_info=True)


def main():
    """Main exporter loop."""
    logger.info(f"Starting QNAP SNMP exporter on port {EXPORTER_PORT}")
    logger.info(f"QNAP host: {QNAP_HOST}")
    logger.info(f"SNMP community: {SNMP_COMMUNITY}")
    logger.info(f"Scrape interval: {SCRAPE_INTERVAL}s")

    # Start Prometheus metrics server
    start_http_server(EXPORTER_PORT)
    logger.info(f"Metrics endpoint available at http://0.0.0.0:{EXPORTER_PORT}/metrics")

    # Create SNMP client
    client = QNAPSNMPClient(QNAP_HOST, SNMP_COMMUNITY, SNMP_PORT)

    # Collection loop
    while True:
        collect_metrics(client, QNAP_HOST)
        time.sleep(SCRAPE_INTERVAL)


if __name__ == '__main__':
    main()
