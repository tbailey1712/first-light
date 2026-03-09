#!/usr/bin/env python3
"""
Proxmox VE Metrics Exporter for Prometheus

Queries Proxmox API for VM/container metrics and exposes them via Prometheus.
Metrics include CPU, RAM, disk usage per VM/container, and storage pool utilization.
"""

import os
import time
import logging
from typing import Dict, List, Any
import requests
from prometheus_client import start_http_server, Gauge, Info
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings if verify_ssl is disabled
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Environment variables
PROXMOX_HOST = os.getenv('PROXMOX_HOST', 'pve.mcducklabs.com')
PROXMOX_PORT = int(os.getenv('PROXMOX_PORT', '8006'))
PROXMOX_TOKEN_ID = os.getenv('PROXMOX_TOKEN_ID', '')
PROXMOX_TOKEN_SECRET = os.getenv('PROXMOX_TOKEN_SECRET', '')
PROXMOX_NODE = os.getenv('PROXMOX_NODE', 'pve')
PROXMOX_VERIFY_SSL = os.getenv('PROXMOX_VERIFY_SSL', 'false').lower() == 'true'
EXPORTER_PORT = int(os.getenv('EXPORTER_PORT', '9002'))
SCRAPE_INTERVAL = int(os.getenv('SCRAPE_INTERVAL', '60'))

# Prometheus metrics
pve_vm_cpu_usage = Gauge('pve_vm_cpu_usage_ratio', 'VM CPU usage ratio', ['vmid', 'name', 'node'])
pve_vm_memory_usage = Gauge('pve_vm_memory_usage_bytes', 'VM memory usage in bytes', ['vmid', 'name', 'node'])
pve_vm_memory_total = Gauge('pve_vm_memory_total_bytes', 'VM total memory in bytes', ['vmid', 'name', 'node'])
pve_vm_disk_usage = Gauge('pve_vm_disk_usage_bytes', 'VM disk usage in bytes', ['vmid', 'name', 'node'])
pve_vm_disk_total = Gauge('pve_vm_disk_total_bytes', 'VM total disk in bytes', ['vmid', 'name', 'node'])
pve_vm_uptime = Gauge('pve_vm_uptime_seconds', 'VM uptime in seconds', ['vmid', 'name', 'node'])
pve_vm_status = Gauge('pve_vm_status', 'VM status (1=running, 0=stopped)', ['vmid', 'name', 'node', 'status'])

pve_ct_cpu_usage = Gauge('pve_ct_cpu_usage_ratio', 'Container CPU usage ratio', ['ctid', 'name', 'node'])
pve_ct_memory_usage = Gauge('pve_ct_memory_usage_bytes', 'Container memory usage in bytes', ['ctid', 'name', 'node'])
pve_ct_memory_total = Gauge('pve_ct_memory_total_bytes', 'Container total memory in bytes', ['ctid', 'name', 'node'])
pve_ct_disk_usage = Gauge('pve_ct_disk_usage_bytes', 'Container disk usage in bytes', ['ctid', 'name', 'node'])
pve_ct_disk_total = Gauge('pve_ct_disk_total_bytes', 'Container total disk in bytes', ['ctid', 'name', 'node'])
pve_ct_uptime = Gauge('pve_ct_uptime_seconds', 'Container uptime in seconds', ['ctid', 'name', 'node'])
pve_ct_status = Gauge('pve_ct_status', 'Container status (1=running, 0=stopped)', ['ctid', 'name', 'node', 'status'])

pve_storage_usage = Gauge('pve_storage_usage_bytes', 'Storage usage in bytes', ['storage', 'node'])
pve_storage_total = Gauge('pve_storage_total_bytes', 'Storage total capacity in bytes', ['storage', 'node'])

pve_node_cpu_usage = Gauge('pve_node_cpu_usage_ratio', 'Node CPU usage ratio', ['node'])
pve_node_memory_usage = Gauge('pve_node_memory_usage_bytes', 'Node memory usage in bytes', ['node'])
pve_node_memory_total = Gauge('pve_node_memory_total_bytes', 'Node total memory in bytes', ['node'])

pve_info = Info('pve_exporter', 'Proxmox VE exporter information')


class ProxmoxAPI:
    """Proxmox VE API client."""

    def __init__(self, host: str, port: int, token_id: str, token_secret: str, verify_ssl: bool = False):
        self.base_url = f"https://{host}:{port}/api2/json"
        self.headers = {
            "Authorization": f"PVEAPIToken={token_id}={token_secret}"
        }
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def _get(self, endpoint: str) -> Dict[str, Any]:
        """Make GET request to Proxmox API."""
        url = f"{self.base_url}{endpoint}"
        try:
            response = self.session.get(url, verify=self.verify_ssl, timeout=10)
            response.raise_for_status()
            return response.json().get('data', {})
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {url} - {e}")
            return {}

    def get_cluster_resources(self) -> List[Dict[str, Any]]:
        """Get all cluster resources (VMs, containers, storage, nodes)."""
        return self._get('/cluster/resources')

    def get_node_status(self, node: str) -> Dict[str, Any]:
        """Get node status."""
        return self._get(f'/nodes/{node}/status')

    def get_vm_status(self, node: str, vmid: int) -> Dict[str, Any]:
        """Get VM current status."""
        return self._get(f'/nodes/{node}/qemu/{vmid}/status/current')

    def get_ct_status(self, node: str, ctid: int) -> Dict[str, Any]:
        """Get container current status."""
        return self._get(f'/nodes/{node}/lxc/{ctid}/status/current')


def collect_metrics(api: ProxmoxAPI, node: str):
    """Collect metrics from Proxmox and update Prometheus gauges."""
    logger.info("Collecting metrics from Proxmox...")

    try:
        # Get all cluster resources
        resources = api.get_cluster_resources()

        for resource in resources:
            res_type = resource.get('type')
            res_node = resource.get('node', node)

            # VM metrics
            if res_type == 'qemu':
                vmid = str(resource.get('vmid', ''))
                name = resource.get('name', 'unknown')
                status = resource.get('status', 'unknown')

                # Get detailed status
                vm_status = api.get_vm_status(res_node, vmid)
                if vm_status:
                    cpu = vm_status.get('cpu', 0)
                    mem = vm_status.get('mem', 0)
                    maxmem = vm_status.get('maxmem', 0)
                    disk = vm_status.get('disk', 0)
                    maxdisk = vm_status.get('maxdisk', 0)
                    uptime = vm_status.get('uptime', 0)

                    pve_vm_cpu_usage.labels(vmid=vmid, name=name, node=res_node).set(cpu)
                    pve_vm_memory_usage.labels(vmid=vmid, name=name, node=res_node).set(mem)
                    pve_vm_memory_total.labels(vmid=vmid, name=name, node=res_node).set(maxmem)
                    pve_vm_disk_usage.labels(vmid=vmid, name=name, node=res_node).set(disk)
                    pve_vm_disk_total.labels(vmid=vmid, name=name, node=res_node).set(maxdisk)
                    pve_vm_uptime.labels(vmid=vmid, name=name, node=res_node).set(uptime)
                    pve_vm_status.labels(vmid=vmid, name=name, node=res_node, status=status).set(1 if status == 'running' else 0)

            # Container metrics
            elif res_type == 'lxc':
                ctid = str(resource.get('vmid', ''))
                name = resource.get('name', 'unknown')
                status = resource.get('status', 'unknown')

                # Get detailed status
                ct_status = api.get_ct_status(res_node, ctid)
                if ct_status:
                    cpu = ct_status.get('cpu', 0)
                    mem = ct_status.get('mem', 0)
                    maxmem = ct_status.get('maxmem', 0)
                    disk = ct_status.get('disk', 0)
                    maxdisk = ct_status.get('maxdisk', 0)
                    uptime = ct_status.get('uptime', 0)

                    pve_ct_cpu_usage.labels(ctid=ctid, name=name, node=res_node).set(cpu)
                    pve_ct_memory_usage.labels(ctid=ctid, name=name, node=res_node).set(mem)
                    pve_ct_memory_total.labels(ctid=ctid, name=name, node=res_node).set(maxmem)
                    pve_ct_disk_usage.labels(ctid=ctid, name=name, node=res_node).set(disk)
                    pve_ct_disk_total.labels(ctid=ctid, name=name, node=res_node).set(maxdisk)
                    pve_ct_uptime.labels(ctid=ctid, name=name, node=res_node).set(uptime)
                    pve_ct_status.labels(ctid=ctid, name=name, node=res_node, status=status).set(1 if status == 'running' else 0)

            # Storage metrics
            elif res_type == 'storage':
                storage = resource.get('storage', 'unknown')
                disk = resource.get('disk', 0)
                maxdisk = resource.get('maxdisk', 0)

                pve_storage_usage.labels(storage=storage, node=res_node).set(disk)
                pve_storage_total.labels(storage=storage, node=res_node).set(maxdisk)

            # Node metrics
            elif res_type == 'node':
                node_name = resource.get('node', 'unknown')
                cpu = resource.get('cpu', 0)
                mem = resource.get('mem', 0)
                maxmem = resource.get('maxmem', 0)

                pve_node_cpu_usage.labels(node=node_name).set(cpu)
                pve_node_memory_usage.labels(node=node_name).set(mem)
                pve_node_memory_total.labels(node=node_name).set(maxmem)

        logger.info(f"Metrics collection completed. Found {len(resources)} resources.")

    except Exception as e:
        logger.error(f"Error collecting metrics: {e}", exc_info=True)


def main():
    """Main exporter loop."""
    # Validate configuration
    if not PROXMOX_TOKEN_ID or not PROXMOX_TOKEN_SECRET:
        logger.error("PROXMOX_TOKEN_ID and PROXMOX_TOKEN_SECRET must be set")
        return

    logger.info(f"Starting Proxmox VE exporter on port {EXPORTER_PORT}")
    logger.info(f"Proxmox host: {PROXMOX_HOST}:{PROXMOX_PORT}")
    logger.info(f"Node: {PROXMOX_NODE}")
    logger.info(f"Scrape interval: {SCRAPE_INTERVAL}s")
    logger.info(f"SSL verification: {PROXMOX_VERIFY_SSL}")

    # Set exporter info
    pve_info.info({
        'version': '1.0.0',
        'proxmox_host': PROXMOX_HOST,
        'proxmox_node': PROXMOX_NODE
    })

    # Initialize Proxmox API client
    api = ProxmoxAPI(
        host=PROXMOX_HOST,
        port=PROXMOX_PORT,
        token_id=PROXMOX_TOKEN_ID,
        token_secret=PROXMOX_TOKEN_SECRET,
        verify_ssl=PROXMOX_VERIFY_SSL
    )

    # Start Prometheus HTTP server
    start_http_server(EXPORTER_PORT)
    logger.info(f"Metrics endpoint available at http://0.0.0.0:{EXPORTER_PORT}/metrics")

    # Collect metrics periodically
    while True:
        collect_metrics(api, PROXMOX_NODE)
        time.sleep(SCRAPE_INTERVAL)


if __name__ == '__main__':
    main()
