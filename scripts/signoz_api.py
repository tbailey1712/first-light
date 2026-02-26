#!/usr/bin/env python3
"""
SigNoz API automation for First Light
Creates saved views, alerts, and dashboards via API
"""

import os
import json
import time
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any

class SigNozAPI:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            'Content-Type': 'application/json',
            'SIGNOZ-API-KEY': api_key
        }

    def query_logs(self, filter_expression: str, limit: int = 100,
                   hours_back: int = 1) -> Dict[str, Any]:
        """Query logs with a filter expression"""
        end_time = int(time.time() * 1000)
        start_time = end_time - (hours_back * 3600 * 1000)

        payload = {
            "start": start_time,
            "end": end_time,
            "requestType": "raw",
            "variables": {},
            "compositeQuery": {
                "queries": [{
                    "type": "builder_query",
                    "spec": {
                        "name": "A",
                        "signal": "logs",
                        "filter": {
                            "expression": filter_expression
                        },
                        "order": [
                            {"key": {"name": "timestamp"}, "direction": "desc"},
                            {"key": {"name": "id"}, "direction": "desc"}
                        ],
                        "offset": 0,
                        "limit": limit
                    }
                }]
            }
        }

        response = requests.post(
            f"{self.base_url}/api/v5/query_range",
            headers=self.headers,
            json=payload
        )
        response.raise_for_status()
        return response.json()

    def test_filter(self, filter_expression: str, name: str = "") -> bool:
        """Test if a filter returns results"""
        print(f"\nTesting filter: {name}")
        print(f"Expression: {filter_expression}")

        try:
            result = self.query_logs(filter_expression, limit=5)

            if result.get('status') == 'success':
                rows = result.get('data', {}).get('data', {}).get('results', [{}])[0].get('rows')

                if rows is None:
                    print(f"⚠️  No results (empty dataset)")
                    return True  # Query worked, just no matching logs

                count = len(rows)
                print(f"✅ Success: Found {count} results")

                if count > 0:
                    # Show first result summary
                    first_log = rows[0]['data']
                    host = first_log.get('resources_string', {}).get('host.name', 'unknown')
                    severity = first_log.get('severity_text', 'unknown')
                    print(f"   Sample: host={host}, severity={severity}")

                return True
            else:
                error_msg = result.get('error', {}).get('message', 'Unknown error')
                errors = result.get('error', {}).get('errors', [])
                print(f"❌ Error: {error_msg}")
                for err in errors:
                    print(f"   - {err.get('message', '')}")
                return False

        except Exception as e:
            print(f"❌ Exception: {str(e)}")
            import traceback
            traceback.print_exc()
            return False


def main():
    # Load configuration
    base_url = os.getenv('SIGNOZ_URL', 'http://192.168.2.106:8081')
    api_key = os.getenv('SIGNOZ_API_KEY')

    if not api_key:
        print("❌ SIGNOZ_API_KEY environment variable not set!")
        print("   export SIGNOZ_API_KEY='your-key-here'")
        return 1

    api = SigNozAPI(base_url, api_key)

    # Define all saved views
    saved_views = [
        {
            "name": "Security Events",
            "filter": "pfsense.action = 'block' OR severity_text IN ('WARN', 'ERROR', 'CRITICAL')",
            "description": "All blocked traffic and warnings/errors"
        },
        {
            "name": "Firewall Blocks",
            "filter": "host.name = 'firewall.mcducklabs.com' AND pfsense.action = 'block'",
            "description": "All blocked traffic on pfSense"
        },
        {
            "name": "External Inbound Traffic",
            "filter": "pfsense.action = 'block' AND pfsense.direction = 'in' AND NOT (pfsense.src_ip LIKE '192.168.%' OR pfsense.src_ip LIKE '10.%' OR pfsense.src_ip LIKE '172.16.%')",
            "description": "Inbound traffic from public IPs"
        },
        {
            "name": "Authentication Failures",
            "filter": "body LIKE '%failed%' AND (body LIKE '%auth%' OR body LIKE '%login%' OR body LIKE '%ssh%' OR body LIKE '%password%')",
            "description": "Failed login attempts across all devices"
        },
        {
            "name": "Per-Device: pfSense",
            "filter": "host.name = 'firewall.mcducklabs.com'",
            "description": "All logs from pfSense firewall"
        },
        {
            "name": "Per-Device: QNAP NAS",
            "filter": "host.name = 'nas'",
            "description": "All logs from QNAP NAS"
        },
        {
            "name": "Per-Device: Proxmox",
            "filter": "host.name = 'pve'",
            "description": "All logs from Proxmox hypervisor"
        },
        {
            "name": "Per-Device: Home Assistant",
            "filter": "host.name = 'ha'",
            "description": "All logs from Home Assistant"
        },
        {
            "name": "All Warnings and Errors",
            "filter": "severity_text IN ('WARN', 'ERROR', 'CRITICAL', 'FATAL')",
            "description": "All elevated severity logs"
        }
    ]

    print("=" * 60)
    print("TESTING SAVED VIEW FILTERS")
    print("=" * 60)

    results = []
    for view in saved_views:
        success = api.test_filter(view['filter'], view['name'])
        results.append({
            'name': view['name'],
            'filter': view['filter'],
            'success': success
        })
        time.sleep(0.5)  # Rate limiting

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    success_count = sum(1 for r in results if r['success'])
    print(f"\n✅ {success_count}/{len(results)} filters working")

    if success_count < len(results):
        print("\n❌ Failed filters:")
        for r in results:
            if not r['success']:
                print(f"   - {r['name']}")

    return 0 if success_count == len(results) else 1


if __name__ == '__main__':
    exit(main())
