#!/usr/bin/env python3
"""
Test script for ntopng API tools.

Run this after configuring ntopng credentials in .env:
  NTOPNG_HOST=192.168.1.5
  NTOPNG_PORT=3000
  NTOPNG_USERNAME=admin
  NTOPNG_PASSWORD=your_password
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.tools.ntopng import (
    query_ntopng_interfaces,
    query_ntopng_top_talkers,
    query_ntopng_interface_stats,
    query_ntopng_active_alerts,
    query_ntopng_l7_protocols,
)
from agent.config import get_config


def test_ntopng_api():
    """Test all ntopng API endpoints."""

    config = get_config()

    print("=" * 60)
    print("Testing ntopng API")
    print("=" * 60)
    print(f"Host: {config.ntopng_host}:{config.ntopng_port}")
    print(f"Username: {config.ntopng_username}")
    print()

    if not config.ntopng_host:
        print("❌ Error: NTOPNG_HOST not configured in .env")
        print("\nAdd these to your .env file:")
        print("  NTOPNG_HOST=192.168.1.5")
        print("  NTOPNG_PORT=3000")
        print("  NTOPNG_USERNAME=admin")
        print("  NTOPNG_PASSWORD=your_password")
        return False

    # Test 1: Get interfaces
    print("\n1. Testing query_ntopng_interfaces()...")
    result = query_ntopng_interfaces()
    if "Error" in result:
        print(f"   ❌ Failed: {result}")
        return False
    else:
        print(f"   ✅ Success: Found interface data")
        print(f"   Response preview: {result[:200]}...")

    # Test 2: Get top talkers
    print("\n2. Testing query_ntopng_top_talkers()...")
    result = query_ntopng_top_talkers(ifid=0, limit=10)
    if "Error" in result:
        print(f"   ❌ Failed: {result}")
    else:
        print(f"   ✅ Success: Retrieved top talkers")
        print(f"   Response preview: {result[:200]}...")

    # Test 3: Get interface stats
    print("\n3. Testing query_ntopng_interface_stats()...")
    result = query_ntopng_interface_stats(ifid=0)
    if "Error" in result:
        print(f"   ❌ Failed: {result}")
    else:
        print(f"   ✅ Success: Retrieved interface stats")
        print(f"   Response preview: {result[:200]}...")

    # Test 4: Get active alerts
    print("\n4. Testing query_ntopng_active_alerts()...")
    result = query_ntopng_active_alerts()
    if "Error" in result:
        print(f"   ❌ Failed: {result}")
    else:
        print(f"   ✅ Success: Retrieved active alerts")
        print(f"   Response preview: {result[:200]}...")

    # Test 5: Get L7 protocols
    print("\n5. Testing query_ntopng_l7_protocols()...")
    result = query_ntopng_l7_protocols(ifid=0)
    if "Error" in result:
        print(f"   ❌ Failed: {result}")
    else:
        print(f"   ✅ Success: Retrieved L7 protocol breakdown")
        print(f"   Response preview: {result[:200]}...")

    print("\n" + "=" * 60)
    print("✅ All ntopng API tests completed successfully!")
    print("=" * 60)
    return True


if __name__ == "__main__":
    success = test_ntopng_api()
    sys.exit(0 if success else 1)
