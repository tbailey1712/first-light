#!/usr/bin/env python3
"""
QNAP NAS SNMP Exporter for Prometheus

Queries QNAP NAS via SNMPv2c and exposes metrics for:
- CPU usage and system temperature
- Memory (RAM total + used)
- Disk temperatures, SMART status, and model names
- Fan speeds (RPM) — System FAN 1/2/3
- Per-ZFS-dataset filesystem usage (size, used, used%) via hrStorageTable
- Network interface TX/RX byte counters
- System uptime

QNAP Enterprise MIB OIDs (1.3.6.1.4.1.24681.1.2.x):
  .1.0   CPU usage %
  .2.0   Total RAM (MB, string)
  .6.0   System temperature (°C/°F string)
  .9.x   Network interface table (name, rx, tx)
  .11.x  Disk table (name, temp, SMART status, bad_sectors, model, capacity)
  .15.x  Fan table (name, RPM)
  .17.x  Volume/pool table (name, RAID type, total, free, status)

Standard hrStorageTable (1.3.6.1.2.1.25.2.3.1.x):
  .2  hrStorageType
  .3  hrStorageDescr (mount path)
  .4  hrStorageAllocationUnits (bytes per unit)
  .5  hrStorageSize (in units)
  .6  hrStorageUsed (in units)
"""

import os
import re
import subprocess
import time
import logging
from typing import Dict, List, Optional, Tuple

from prometheus_client import start_http_server, Gauge, Counter

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)

QNAP_HOST = os.getenv('QNAP_HOST', 'nas.mcducklabs.com')
SNMP_COMMUNITY = os.getenv('SNMP_COMMUNITY', 'public')
SNMP_PORT = int(os.getenv('SNMP_PORT', '161'))
EXPORTER_PORT = int(os.getenv('EXPORTER_PORT', '9003'))
SCRAPE_INTERVAL = int(os.getenv('SCRAPE_INTERVAL', '60'))

# ── QNAP Enterprise MIB OIDs ─────────────────────────────────────────────────
OID_BASE = '1.3.6.1.4.1.24681'
OID_CPU_USAGE   = f'{OID_BASE}.1.2.1.0'   # "38.6 %"
OID_RAM_TOTAL   = f'{OID_BASE}.1.2.2.0'   # "15308.2 MB"
OID_SYS_TEMP    = f'{OID_BASE}.1.2.6.0'   # "46 C/115 F"  (note: NOT .2.5.0)
OID_IF_TABLE    = f'{OID_BASE}.1.2.9'     # Network interface table
OID_DISK_TABLE  = f'{OID_BASE}.1.2.11'    # Disk table
OID_FAN_TABLE   = f'{OID_BASE}.1.2.15'    # Fan table
OID_VOL_TABLE   = f'{OID_BASE}.1.2.17'    # Volume/pool table

# Standard hrStorageTable
OID_HR_STORAGE  = '1.3.6.1.2.1.25.2.3.1'
OID_HR_UPTIME   = '1.3.6.1.2.1.25.1.1.0'

# hrStorageType OIDs (used to classify entries)
HR_TYPE_RAM         = '1.3.6.1.2.1.25.2.1.2'
HR_TYPE_FIXED_DISK  = '1.3.6.1.2.1.25.2.1.4'

# ZFS dataset paths we care about — anything starting with these prefixes
FS_INCLUDE_PREFIXES = (
    '/zpool',
    '/share/ZFS',
    '/share/external',
    '/share/NFSv',
)

# ── Prometheus metrics ────────────────────────────────────────────────────────
qnap_uptime_seconds         = Gauge('qnap_uptime_seconds',          'System uptime in seconds',              ['host'])
qnap_cpu_usage              = Gauge('qnap_cpu_usage_percent',        'CPU usage %',                           ['host'])
qnap_system_temp            = Gauge('qnap_system_temp_celsius',      'System temperature °C',                 ['host'])
qnap_memory_total           = Gauge('qnap_memory_total_bytes',       'Total RAM bytes',                       ['host'])
qnap_memory_used            = Gauge('qnap_memory_used_bytes',        'Used RAM bytes',                        ['host'])

qnap_disk_temp              = Gauge('qnap_disk_temp_celsius',        'Disk temperature °C',                   ['host', 'disk', 'model'])
qnap_disk_status            = Gauge('qnap_disk_status',             'SMART status (1=GOOD, 0=FAIL/--)',       ['host', 'disk', 'model'])

qnap_fan_speed              = Gauge('qnap_fan_speed_rpm',            'Fan speed in RPM',                      ['host', 'fan'])

qnap_fs_size_bytes          = Gauge('qnap_filesystem_size_bytes',    'Filesystem total size bytes',           ['host', 'mount'])
qnap_fs_used_bytes          = Gauge('qnap_filesystem_used_bytes',    'Filesystem used bytes',                 ['host', 'mount'])
qnap_fs_used_percent        = Gauge('qnap_filesystem_used_percent',  'Filesystem used %',                     ['host', 'mount'])

qnap_volume_size            = Gauge('qnap_volume_size_bytes',        'QNAP volume pool total bytes',          ['host', 'volume'])
qnap_volume_free            = Gauge('qnap_volume_free_bytes',        'QNAP volume pool free bytes',           ['host', 'volume'])
qnap_volume_used            = Gauge('qnap_volume_used_bytes',        'QNAP volume pool used bytes',           ['host', 'volume'])

qnap_if_rx_bytes            = Counter('qnap_interface_rx_bytes_total', 'Network interface RX bytes',          ['host', 'interface'])
qnap_if_tx_bytes            = Counter('qnap_interface_tx_bytes_total', 'Network interface TX bytes',          ['host', 'interface'])


# ── SNMP client ───────────────────────────────────────────────────────────────

class SNMPClient:
    def __init__(self, host: str, community: str, port: int = 161):
        self.host = host
        self.community = community
        self.port = port

    def get(self, oid: str) -> Optional[str]:
        try:
            result = subprocess.run(
                ['snmpget', '-v', '2c', '-c', self.community, '-Oqv',
                 f'{self.host}:{self.port}', oid],
                capture_output=True, text=True, timeout=5,
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except Exception as e:
            logger.debug(f"snmpget {oid}: {e}")
            return None

    def walk(self, oid: str, timeout: int = 30) -> List[Tuple[str, str]]:
        """Walk OID tree; returns [(oid_suffix, value), ...]."""
        try:
            result = subprocess.run(
                ['snmpwalk', '-v', '2c', '-c', self.community, '-Oen',
                 f'{self.host}:{self.port}', oid],
                capture_output=True, text=True, timeout=timeout,
            )
            if result.returncode != 0:
                return []
            rows = []
            for line in result.stdout.splitlines():
                parts = line.split(' = ', 1)
                if len(parts) != 2:
                    continue
                oid_part = parts[0].strip()
                val_part = parts[1].strip()
                # Strip type prefix ("STRING: ", "INTEGER: ", etc.)
                val = val_part.split(': ', 1)[1].strip('"') if ': ' in val_part else val_part
                rows.append((oid_part, val))
            return rows
        except Exception as e:
            logger.debug(f"snmpwalk {oid}: {e}")
            return []


# ── Parsers ───────────────────────────────────────────────────────────────────

def parse_temp(s: str) -> Optional[float]:
    """Parse '46 C/115 F' → 46.0"""
    m = re.search(r'(\d+)\s*C', s)
    return float(m.group(1)) if m else None


def parse_pct(s: str) -> Optional[float]:
    """Parse '38.6 %' → 38.6"""
    m = re.search(r'([\d.]+)\s*%', s)
    return float(m.group(1)) if m else None


def parse_rpm(s: str) -> Optional[float]:
    """Parse '7102 RPM' → 7102.0"""
    m = re.search(r'(\d+)\s*RPM', s, re.IGNORECASE)
    return float(m.group(1)) if m else None


def parse_size_str(s: str) -> Optional[float]:
    """Parse '14.55 TB' / '465.76 GB' / '1.82 TB' → bytes"""
    m = re.search(r'([\d.]+)\s*(TB|GB|MB|KB)', s, re.IGNORECASE)
    if not m:
        return None
    v, u = float(m.group(1)), m.group(2).upper()
    return v * {'KB': 1024, 'MB': 1024**2, 'GB': 1024**3, 'TB': 1024**4}[u]


def last_two(oid: str) -> Tuple[str, str]:
    """Extract (field, index) from OID tail — '...1.2.11.1.3.2' → ('3', '2')"""
    parts = oid.split('.')
    return parts[-2], parts[-1]


# ── Collection ────────────────────────────────────────────────────────────────

def collect_metrics(client: SNMPClient, hostname: str):
    logger.info("Collecting QNAP SNMP metrics...")

    # ── Uptime ────────────────────────────────────────────────────────────────
    uptime_raw = client.get(OID_HR_UPTIME)
    if uptime_raw:
        try:
            qnap_uptime_seconds.labels(host=hostname).set(int(uptime_raw) / 100)
        except ValueError:
            pass

    # ── CPU ───────────────────────────────────────────────────────────────────
    cpu_raw = client.get(OID_CPU_USAGE)
    if cpu_raw:
        v = parse_pct(cpu_raw)
        if v is not None:
            qnap_cpu_usage.labels(host=hostname).set(v)

    # ── System temperature ────────────────────────────────────────────────────
    temp_raw = client.get(OID_SYS_TEMP)
    if temp_raw:
        v = parse_temp(temp_raw)
        if v is not None:
            qnap_system_temp.labels(host=hostname).set(v)

    # ── RAM (from QNAP enterprise MIB .2.0 — total; hrStorage index 1 — used) ─
    ram_total_raw = client.get(OID_RAM_TOTAL)
    if ram_total_raw:
        m = re.search(r'([\d.]+)\s*MB', ram_total_raw, re.IGNORECASE)
        if m:
            total_b = float(m.group(1)) * 1024 * 1024
            qnap_memory_total.labels(host=hostname).set(total_b)
            # Get used from hrStorage physical memory entry (index 1)
            used_raw = client.get(f'{OID_HR_STORAGE}.6.1')  # hrStorageUsed
            unit_raw = client.get(f'{OID_HR_STORAGE}.4.1')  # hrStorageAllocationUnits
            if used_raw and unit_raw:
                try:
                    unit_b = int(unit_raw.split()[0])
                    used_b = int(used_raw) * unit_b
                    qnap_memory_used.labels(host=hostname).set(used_b)
                except (ValueError, IndexError):
                    pass

    # ── Disks ─────────────────────────────────────────────────────────────────
    # Fields: 2=name, 3=temp, 4=SMART_status, 5=model, 6=capacity, 7=GOOD/FAIL
    disk_table = client.walk(OID_DISK_TABLE)
    disks: Dict[str, dict] = {}
    for oid, val in disk_table:
        field, idx = last_two(oid)
        d = disks.setdefault(idx, {})
        if field == '2':
            d['name'] = val
        elif field == '3':
            t = parse_temp(val)
            if t is not None:
                d['temp'] = t
        elif field == '5':
            d['model'] = val
        elif field == '7':
            # "GOOD" / "--" / "FAIL"
            d['smart'] = 1 if val.upper() == 'GOOD' else (0 if val != '--' else -1)

    for idx, d in disks.items():
        name  = d.get('name', f'disk{idx}')
        model = d.get('model', 'unknown')
        if model == '--':
            model = 'empty'
        if 'temp' in d:
            qnap_disk_temp.labels(host=hostname, disk=name, model=model).set(d['temp'])
        smart = d.get('smart', -1)
        if smart >= 0:
            qnap_disk_status.labels(host=hostname, disk=name, model=model).set(smart)

    # ── Fans ──────────────────────────────────────────────────────────────────
    # Fields: 2=fan_name ("System FAN 1"), 3=RPM ("7102 RPM")
    fan_table = client.walk(OID_FAN_TABLE)
    fans: Dict[str, dict] = {}
    for oid, val in fan_table:
        field, idx = last_two(oid)
        f = fans.setdefault(idx, {})
        if field == '2':
            f['name'] = val
        elif field == '3':
            rpm = parse_rpm(val)
            if rpm is not None:
                f['rpm'] = rpm

    for idx, f in fans.items():
        if 'name' in f and 'rpm' in f:
            qnap_fan_speed.labels(host=hostname, fan=f['name']).set(f['rpm'])

    # ── Volume/pool table (QNAP enterprise — coarse pool-level data) ──────────
    # Fields: 2=name, 3=RAID_type, 4=total_size_str, 5=free_size_str, 6=status
    vol_table = client.walk(OID_VOL_TABLE)
    vols: Dict[str, dict] = {}
    for oid, val in vol_table:
        field, idx = last_two(oid)
        v = vols.setdefault(idx, {})
        if field == '2':
            v['name'] = val
        elif field == '4':
            sz = parse_size_str(val)
            if sz:
                v['total'] = sz
        elif field == '5':
            sz = parse_size_str(val)
            if sz:
                v['free'] = sz

    for idx, v in vols.items():
        name = v.get('name', f'volume{idx}')
        if 'total' in v:
            qnap_volume_size.labels(host=hostname, volume=name).set(v['total'])
        if 'free' in v:
            qnap_volume_free.labels(host=hostname, volume=name).set(v['free'])
            if 'total' in v:
                qnap_volume_used.labels(host=hostname, volume=name).set(v['total'] - v['free'])

    # ── hrStorageTable — per-ZFS-dataset filesystem usage ─────────────────────
    # Walk the full hrStorage table in one shot, parse all fields, then filter.
    # We only emit metrics for FixedDisk entries under our target path prefixes.
    storage_table = client.walk(OID_HR_STORAGE, timeout=45)

    fs: Dict[str, dict] = {}
    for oid, val in storage_table:
        field, idx = last_two(oid)
        e = fs.setdefault(idx, {})
        if field == '2':    # hrStorageType (OID string)
            e['type'] = val
        elif field == '3':  # hrStorageDescr (mount path)
            e['descr'] = val
        elif field == '4':  # hrStorageAllocationUnits
            try:
                e['unit'] = int(val.split()[0])
            except (ValueError, IndexError):
                pass
        elif field == '5':  # hrStorageSize
            try:
                e['size'] = int(val)
            except ValueError:
                pass
        elif field == '6':  # hrStorageUsed
            try:
                e['used'] = int(val)
            except ValueError:
                pass

    for idx, e in fs.items():
        # Only FixedDisk entries whose mount matches our prefixes
        if not e.get('type', '').endswith(HR_TYPE_FIXED_DISK.split('.')[-1]):
            # The type OID comes back as the full OID string; check suffix
            fs_type = e.get('type', '')
            if HR_TYPE_FIXED_DISK not in fs_type and '1.4' not in fs_type:
                continue

        descr = e.get('descr', '')
        if not any(descr.startswith(p) for p in FS_INCLUDE_PREFIXES):
            continue

        unit  = e.get('unit', 1)
        size  = e.get('size', 0)
        used  = e.get('used', 0)
        if size == 0:
            continue

        size_b = size * unit
        used_b = used * unit
        used_pct = (used / size) * 100

        qnap_fs_size_bytes.labels(host=hostname, mount=descr).set(size_b)
        qnap_fs_used_bytes.labels(host=hostname, mount=descr).set(used_b)
        qnap_fs_used_percent.labels(host=hostname, mount=descr).set(used_pct)

        logger.debug(f"FS {descr}: {used_b/(1024**3):.1f}/{size_b/(1024**3):.1f} GiB ({used_pct:.1f}%)")

    # ── Network interfaces ─────────────────────────────────────────────────────
    # Fields: 2=ifname, 3=rx_bytes, 4=tx_bytes
    if_table = client.walk(OID_IF_TABLE)
    ifaces: Dict[str, dict] = {}
    for oid, val in if_table:
        field, idx = last_two(oid)
        i = ifaces.setdefault(idx, {})
        if field == '2':
            i['name'] = val
        elif field == '3':
            try:
                i['rx'] = int(val)
            except ValueError:
                pass
        elif field == '4':
            try:
                i['tx'] = int(val)
            except ValueError:
                pass

    for idx, i in ifaces.items():
        name = i.get('name', f'eth{idx}')
        if 'rx' in i:
            qnap_if_rx_bytes.labels(host=hostname, interface=name).inc(i['rx'])
        if 'tx' in i:
            qnap_if_tx_bytes.labels(host=hostname, interface=name).inc(i['tx'])

    logger.info("QNAP SNMP metrics collection complete")


def main():
    logger.info(f"Starting QNAP SNMP exporter on :{EXPORTER_PORT}")
    logger.info(f"Target: {QNAP_HOST}:{SNMP_PORT}, community={SNMP_COMMUNITY}, interval={SCRAPE_INTERVAL}s")
    start_http_server(EXPORTER_PORT)
    client = SNMPClient(QNAP_HOST, SNMP_COMMUNITY, SNMP_PORT)
    while True:
        collect_metrics(client, QNAP_HOST)
        time.sleep(SCRAPE_INTERVAL)


if __name__ == '__main__':
    main()
