#!/usr/bin/env python3
"""
Audit script to examine log samples from each infrastructure component.
"""

import httpx
import json
from typing import Dict, List

CLICKHOUSE_URL = "http://docker.mcducklabs.com:8123"

def query_clickhouse(query: str) -> str:
    """Execute ClickHouse query via HTTP."""
    with httpx.Client(timeout=30.0) as client:
        response = client.post(
            CLICKHOUSE_URL,
            params={
                "user": "default",
                "password": "",
                "query": query
            }
        )
        if response.status_code != 200:
            raise Exception(f"HTTP {response.status_code}: {response.text}")
        return response.text.strip()

def get_log_samples(host_filter: str, service_filter: str = "", limit: int = 3) -> List[Dict]:
    """Get sample logs for a specific host/service."""
    where_clause = f"resources_string['host.name'] LIKE '%{host_filter}%'"
    if service_filter:
        where_clause += f" AND resources_string['service.name'] LIKE '%{service_filter}%'"

    query = f"""
    SELECT
        resources_string['host.name'] as host,
        resources_string['service.name'] as service,
        body,
        mapKeys(attributes_string) as parsed_fields,
        length(mapKeys(attributes_string)) as num_fields
    FROM signoz_logs.logs_v2
    WHERE timestamp > toUnixTimestamp(now() - INTERVAL 1 HOUR) * 1000000000
      AND {where_clause}
    LIMIT {limit}
    FORMAT JSONEachRow
    """

    result = query_clickhouse(query)
    if not result:
        return []
    return [json.loads(line) for line in result.split('\n') if line]

def audit_system(name: str, host_filter: str, service_filter: str = ""):
    """Audit a single system."""
    print(f"\n{'='*80}")
    print(f"System: {name}")
    print(f"{'='*80}")

    samples = get_log_samples(host_filter, service_filter)

    if not samples:
        print("❌ NO LOGS FOUND")
        return

    print(f"✓ Found {len(samples)} samples")

    for i, sample in enumerate(samples, 1):
        print(f"\n--- Sample {i} ---")
        print(f"Host: {sample['host']}")
        print(f"Service: {sample['service']}")
        print(f"Parsed Fields: {sample['num_fields']} fields")
        if sample['parsed_fields']:
            print(f"  Fields: {', '.join(sample['parsed_fields'])}")
        else:
            print("  Fields: NONE (raw text only)")
        print(f"Body (first 200 chars): {sample['body'][:200]}...")

if __name__ == "__main__":
    print("="*80)
    print("INFRASTRUCTURE LOG PARSING AUDIT")
    print("="*80)

    # UniFi APs
    audit_system("UniFi - First Floor", "ap-first-floor")
    audit_system("UniFi - Second Floor", "ap-second-floor")
    audit_system("UniFi - Basement", "ap-basement")
    audit_system("UniFi - Wolcott", "wolcott")

    # Core infrastructure
    audit_system("pfSense Firewall", "firewall.mcducklabs.com", "filterlog")
    audit_system("ntopng", "ntopng")
    audit_system("Home Assistant", "ha", "homeassistant")
    audit_system("AdGuard", "adguard")
    audit_system("Docker", "docker.mcducklabs.com")
    audit_system("Proxmox", "pve")

    # NAS
    audit_system("NAS/QNAP", "nas")

    # Security events - SSH/sudo
    print(f"\n{'='*80}")
    print(f"System: Security Events (SSH/sudo)")
    print(f"{'='*80}")

    query = """
    SELECT
        resources_string['host.name'] as host,
        resources_string['service.name'] as service,
        body,
        mapKeys(attributes_string) as parsed_fields,
        length(mapKeys(attributes_string)) as num_fields
    FROM signoz_logs.logs_v2
    WHERE timestamp > toUnixTimestamp(now() - INTERVAL 1 HOUR) * 1000000000
      AND (body LIKE '%sshd%' OR body LIKE '%sudo%')
    LIMIT 5
    FORMAT JSONEachRow
    """

    result = query_clickhouse(query)
    if result:
        samples = [json.loads(line) for line in result.split('\n') if line]
        print(f"✓ Found {len(samples)} samples")
        for i, sample in enumerate(samples, 1):
            print(f"\n--- Sample {i} ---")
            print(f"Host: {sample['host']}")
            print(f"Service: {sample['service']}")
            print(f"Parsed Fields: {sample['num_fields']} fields")
            if sample['parsed_fields']:
                print(f"  Fields: {', '.join(sample['parsed_fields'])}")
            else:
                print("  Fields: NONE (raw text only)")
            print(f"Body (first 200 chars): {sample['body'][:200]}...")
    else:
        print("❌ NO LOGS FOUND")

    print(f"\n{'='*80}")
    print("AUDIT COMPLETE")
    print(f"{'='*80}")
