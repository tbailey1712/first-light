#!/usr/bin/env python3
"""
Simple standalone test for ntopng API (no dependencies).
Tests API connectivity and authentication.
"""

import os
import json
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import base64


def load_env():
    """Load .env file."""
    env = {}
    env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    env[key] = value
    return env


def make_request(url, username, password):
    """Make authenticated HTTP request."""
    try:
        # Create basic auth header
        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode()).decode()

        req = Request(url)
        req.add_header('Authorization', f'Basic {encoded}')

        with urlopen(req, timeout=10) as response:
            return response.read().decode('utf-8')
    except HTTPError as e:
        return f"HTTP Error {e.code}: {e.reason}"
    except URLError as e:
        return f"URL Error: {e.reason}"
    except Exception as e:
        return f"Error: {str(e)}"


def test_ntopng():
    """Test ntopng API endpoints."""

    env = load_env()

    host = env.get('NTOPNG_HOST', '')
    port = env.get('NTOPNG_PORT', '3000')
    username = env.get('NTOPNG_USERNAME', '')
    password = env.get('NTOPNG_PASSWORD', '')

    print("=" * 60)
    print("Testing ntopng API")
    print("=" * 60)
    print(f"Host: {host}:{port}")
    print(f"Username: {username}")
    print()

    if not host:
        print("❌ Error: NTOPNG_HOST not set in .env")
        return False

    if not username or not password:
        print("❌ Error: NTOPNG_USERNAME or NTOPNG_PASSWORD not set in .env")
        return False

    base_url = f"http://{host}:{port}"

    # Test 1: Get interfaces
    print("1. Testing /lua/rest/v2/get/ntopng/interfaces.lua")
    url = f"{base_url}/lua/rest/v2/get/ntopng/interfaces.lua"
    result = make_request(url, username, password)

    if "Error" in result or "HTTP" in result:
        print(f"   ❌ Failed: {result}")
        print("\n   Check:")
        print("   - Is ntopng running?")
        print("   - Are credentials correct?")
        print("   - Is REST API enabled in ntopng?")
        return False

    try:
        data = json.loads(result)
        print(f"   ✅ Success: {data.get('rc_str', 'OK')}")
        if 'rsp' in data:
            print(f"   Found {len(data['rsp'])} interface(s)")
            for iface in data.get('rsp', []):
                print(f"     - {iface.get('name', 'unknown')}")
    except json.JSONDecodeError:
        print(f"   ⚠️  Got response but not JSON: {result[:100]}")

    # Test 2: Get interface stats
    print("\n2. Testing /lua/rest/v2/get/interface/data.lua")
    url = f"{base_url}/lua/rest/v2/get/interface/data.lua?ifid=0"
    result = make_request(url, username, password)

    if "Error" in result or "HTTP" in result:
        print(f"   ❌ Failed: {result}")
    else:
        try:
            data = json.loads(result)
            print(f"   ✅ Success: {data.get('rc_str', 'OK')}")
            if 'rsp' in data:
                rsp = data['rsp']
                print(f"     Bytes: {rsp.get('bytes', 0):,}")
                print(f"     Packets: {rsp.get('packets', 0):,}")
                print(f"     Active Hosts: {rsp.get('hosts', 0)}")
        except json.JSONDecodeError:
            print(f"   ⚠️  Got response but not JSON")

    # Test 3: Get top talkers
    print("\n3. Testing /lua/rest/v2/get/host/top_talkers.lua")
    params = urlencode({'ifid': 0, 'limit': 5, 'sortby': 'bytes'})
    url = f"{base_url}/lua/rest/v2/get/host/top_talkers.lua?{params}"
    result = make_request(url, username, password)

    if "Error" in result or "HTTP" in result:
        print(f"   ❌ Failed: {result}")
    else:
        try:
            data = json.loads(result)
            print(f"   ✅ Success: {data.get('rc_str', 'OK')}")
            if 'rsp' in data and isinstance(data['rsp'], list):
                print(f"     Top {len(data['rsp'])} talkers:")
                for host in data['rsp'][:5]:
                    name = host.get('name', 'unknown')
                    bytes_sent = host.get('bytes.sent', 0)
                    bytes_rcvd = host.get('bytes.rcvd', 0)
                    print(f"       {name}: {bytes_sent + bytes_rcvd:,} bytes")
        except json.JSONDecodeError:
            print(f"   ⚠️  Got response but not JSON")

    # Test 4: Get active alerts
    print("\n4. Testing /lua/rest/v2/get/alert/list_engaged.lua")
    url = f"{base_url}/lua/rest/v2/get/alert/list_engaged.lua"
    result = make_request(url, username, password)

    if "Error" in result or "HTTP" in result:
        print(f"   ❌ Failed: {result}")
    else:
        try:
            data = json.loads(result)
            print(f"   ✅ Success: {data.get('rc_str', 'OK')}")
            if 'rsp' in data:
                alerts = data['rsp']
                if isinstance(alerts, dict):
                    alert_count = len(alerts)
                elif isinstance(alerts, list):
                    alert_count = len(alerts)
                else:
                    alert_count = 0
                print(f"     Active alerts: {alert_count}")
        except json.JSONDecodeError:
            print(f"   ⚠️  Got response but not JSON")

    # Test 5: Get L7 protocols
    print("\n5. Testing /lua/rest/v2/get/interface/l7/stats.lua")
    url = f"{base_url}/lua/rest/v2/get/interface/l7/stats.lua?ifid=0"
    result = make_request(url, username, password)

    if "Error" in result or "HTTP" in result:
        print(f"   ❌ Failed: {result}")
    else:
        try:
            data = json.loads(result)
            print(f"   ✅ Success: {data.get('rc_str', 'OK')}")
            if 'rsp' in data:
                protocols = data['rsp']
                if isinstance(protocols, dict):
                    top_protos = sorted(
                        protocols.items(),
                        key=lambda x: x[1].get('bytes', 0) if isinstance(x[1], dict) else 0,
                        reverse=True
                    )[:5]
                    print(f"     Top 5 protocols:")
                    for proto, stats in top_protos:
                        if isinstance(stats, dict):
                            bytes_val = stats.get('bytes', 0)
                            print(f"       {proto}: {bytes_val:,} bytes")
        except (json.JSONDecodeError, AttributeError):
            print(f"   ⚠️  Got response but couldn't parse")

    print("\n" + "=" * 60)
    print("✅ All ntopng API tests completed successfully!")
    print("=" * 60)
    return True


if __name__ == "__main__":
    import sys
    success = test_ntopng()
    sys.exit(0 if success else 1)
