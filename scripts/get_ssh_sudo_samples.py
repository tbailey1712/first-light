#!/usr/bin/env python3
"""
Get sample SSH and sudo logs from ClickHouse to understand format.
"""

import httpx
import json

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

def get_samples(pattern: str, description: str, limit: int = 10):
    """Get sample logs matching a pattern."""
    query = f"""
    SELECT
        resources_string['host.name'] as host,
        resources_string['service.name'] as service,
        body
    FROM signoz_logs.logs_v2
    WHERE timestamp > toUnixTimestamp(now() - INTERVAL 24 HOUR) * 1000000000
      AND body LIKE '%{pattern}%'
    LIMIT {limit}
    FORMAT JSONEachRow
    """

    print(f"\n{'='*80}")
    print(f"{description}")
    print(f"{'='*80}")

    result = query_clickhouse(query)
    if not result:
        print("❌ NO LOGS FOUND")
        return

    samples = [json.loads(line) for line in result.split('\n') if line]
    print(f"✓ Found {len(samples)} samples\n")

    for i, sample in enumerate(samples, 1):
        print(f"--- Sample {i} ---")
        print(f"Host: {sample['host']}")
        print(f"Service: {sample['service']}")
        print(f"Body: {sample['body']}")
        print()

if __name__ == "__main__":
    print("="*80)
    print("SSH/SUDO LOG SAMPLES")
    print("="*80)

    # SSH patterns
    get_samples("sshd", "SSH Daemon Logs (sshd)", 15)
    get_samples("Accepted password", "SSH Successful Logins", 10)
    get_samples("Failed password", "SSH Failed Logins", 10)
    get_samples("Invalid user", "SSH Invalid User Attempts", 10)
    get_samples("Connection closed", "SSH Connection Closed", 10)
    get_samples("Disconnected from", "SSH Disconnections", 10)

    # Sudo patterns
    get_samples("sudo:", "Sudo Commands", 15)
    get_samples("COMMAND=", "Sudo Command Executions", 10)

    print("\n" + "="*80)
    print("SAMPLE COLLECTION COMPLETE")
    print("="*80)
