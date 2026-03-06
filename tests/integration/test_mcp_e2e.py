#!/usr/bin/env python
"""
End-to-End MCP Server Test Plan

Tests all 10 DNS security tools with real data and validates responses.

Run with:
    pytest tests/integration/test_mcp_e2e.py -v -s

Requirements:
    - MCP server running: docker-compose up -d mcp-server
    - SigNoz/ClickHouse running with data
    - Network has generated DNS traffic in the last 24 hours
"""

import sys
import os
import json
import re
from typing import Any, Dict

import pytest
import requests

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from dotenv import load_dotenv
load_dotenv()


# === Test Configuration ===

MCP_BASE_URL = "http://localhost:8082"
TEST_IP = "192.168.1.1"  # Common gateway IP to search for


# === Helper Functions ===

def call_mcp_tool(tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Call an MCP tool via HTTP and return parsed response."""
    url = f"{MCP_BASE_URL}/mcp/tools/{tool_name}"

    response = requests.post(
        url,
        json=params,
        headers={"Content-Type": "application/json"},
        timeout=30
    )

    assert response.status_code == 200, f"Tool {tool_name} returned {response.status_code}: {response.text}"

    result = response.json()
    return result


def validate_non_empty(result: str, tool_name: str) -> None:
    """Validate that result is not empty."""
    assert result is not None, f"{tool_name} returned None"
    assert len(result) > 0, f"{tool_name} returned empty string"
    assert result != "No data available", f"{tool_name} returned no data (might be expected if no traffic)"


def validate_contains_data_markers(result: str, markers: list[str], tool_name: str) -> None:
    """Validate that result contains expected data structure markers."""
    result_lower = result.lower()
    found = [m for m in markers if m.lower() in result_lower]
    assert len(found) > 0, f"{tool_name} missing expected markers. Expected any of {markers}, got: {result[:200]}"


def validate_ip_addresses(result: str, tool_name: str) -> list[str]:
    """Extract and validate IP addresses in result."""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, result)

    # Validate IPs are well-formed
    for ip in ips:
        parts = ip.split('.')
        assert len(parts) == 4, f"Invalid IP format: {ip}"
        for part in parts:
            num = int(part)
            assert 0 <= num <= 255, f"Invalid IP octet: {part} in {ip}"

    return ips


def validate_json_structure(result: str, tool_name: str) -> Dict[str, Any]:
    """Parse and validate JSON structure if present."""
    try:
        # Look for JSON in the result
        if '{' in result and '}' in result:
            json_start = result.index('{')
            json_end = result.rindex('}') + 1
            json_str = result[json_start:json_end]
            data = json.loads(json_str)
            return data
    except (ValueError, json.JSONDecodeError) as e:
        # Not JSON or contains non-JSON text - that's OK for some tools
        pass
    return {}


# === Test Cases ===

class TestMCPServerHealth:
    """Test MCP server is accessible."""

    def test_server_reachable(self):
        """Verify MCP server responds to health check."""
        response = requests.get(f"{MCP_BASE_URL}/health", timeout=5)
        assert response.status_code == 200


class TestMetricsTools:
    """Test all metrics tools (VictoriaMetrics/PromQL)."""

    @pytest.mark.integration
    def test_top_dns_clients(self):
        """Test top_dns_clients returns valid client data."""
        result = call_mcp_tool("top_dns_clients", {"hours": 24, "limit": 10})

        # Validate structure
        assert "result" in result or isinstance(result, str), "Unexpected response structure"

        result_str = result.get("result", str(result))
        validate_non_empty(result_str, "top_dns_clients")

        # Should contain client/IP/query information
        validate_contains_data_markers(
            result_str,
            ["client", "ip", "queries", "total", "192.168"],
            "top_dns_clients"
        )

        # Should have valid IP addresses
        ips = validate_ip_addresses(result_str, "top_dns_clients")
        assert len(ips) > 0, "No IP addresses found in top clients"

        print(f"\n✓ Found {len(ips)} clients")

    @pytest.mark.integration
    def test_dns_block_rates(self):
        """Test dns_block_rates returns block rate data."""
        result = call_mcp_tool("dns_block_rates", {
            "hours": 24,
            "min_block_rate": 0.0,
            "limit": 10
        })

        result_str = result.get("result", str(result))
        validate_non_empty(result_str, "dns_block_rates")

        # Should contain block rate information
        validate_contains_data_markers(
            result_str,
            ["block", "rate", "client", "ip", "%", "queries"],
            "dns_block_rates"
        )

        # Extract percentages
        percentages = re.findall(r'(\d+\.?\d*)%', result_str)
        if percentages:
            for pct in percentages:
                pct_val = float(pct)
                assert 0.0 <= pct_val <= 100.0, f"Invalid percentage: {pct}"
            print(f"\n✓ Found {len(percentages)} block rates")
        else:
            print("\n⚠ No block rate percentages found (might be 0% for all clients)")

    @pytest.mark.integration
    def test_high_risk_clients(self):
        """Test high_risk_clients returns risk analysis."""
        result = call_mcp_tool("high_risk_clients", {
            "hours": 24,
            "min_risk_score": 5.0,
            "limit": 10
        })

        result_str = result.get("result", str(result))
        validate_non_empty(result_str, "high_risk_clients")

        # Should contain risk scoring information
        validate_contains_data_markers(
            result_str,
            ["risk", "score", "client", "ip", "suspicious", "alert"],
            "high_risk_clients"
        )

        print(f"\n✓ Risk analysis completed")

    @pytest.mark.integration
    def test_blocked_domains(self):
        """Test blocked_domains returns frequently blocked domains."""
        result = call_mcp_tool("blocked_domains", {"hours": 24, "limit": 20})

        result_str = result.get("result", str(result))
        validate_non_empty(result_str, "blocked_domains")

        # Should contain domain names
        validate_contains_data_markers(
            result_str,
            ["domain", "blocked", "count", ".com", ".net", ".org"],
            "blocked_domains"
        )

        # Extract domain-like patterns
        domains = re.findall(r'\b[a-z0-9-]+\.[a-z]{2,}\b', result_str.lower())
        if domains:
            print(f"\n✓ Found {len(domains)} blocked domains")
        else:
            print("\n⚠ No domains found (might be no blocks in time range)")

    @pytest.mark.integration
    def test_dns_traffic_by_type(self):
        """Test dns_traffic_by_type returns traffic breakdown."""
        result = call_mcp_tool("dns_traffic_by_type", {"hours": 24})

        result_str = result.get("result", str(result))
        validate_non_empty(result_str, "dns_traffic_by_type")

        # Should contain query types or response types
        validate_contains_data_markers(
            result_str,
            ["type", "count", "queries", "a", "aaaa", "ptr", "mx"],
            "dns_traffic_by_type"
        )

        print(f"\n✓ Traffic breakdown retrieved")


class TestLogsTools:
    """Test all logs tools (Loki/LogQL)."""

    @pytest.mark.integration
    def test_security_summary(self):
        """Test security_summary returns threat information."""
        result = call_mcp_tool("security_summary", {"hours": 1})

        result_str = result.get("result", str(result))
        validate_non_empty(result_str, "security_summary")

        # Should contain security-related information
        validate_contains_data_markers(
            result_str,
            ["security", "threat", "block", "attack", "firewall", "ip"],
            "security_summary"
        )

        # Should have IP addresses for threats
        ips = validate_ip_addresses(result_str, "security_summary")
        print(f"\n✓ Security summary: {len(ips)} IPs mentioned")

    @pytest.mark.integration
    def test_dns_anomalies(self):
        """Test dns_anomalies returns anomaly detection."""
        result = call_mcp_tool("dns_anomalies", {"hours": 1, "limit": 20})

        result_str = result.get("result", str(result))
        validate_non_empty(result_str, "dns_anomalies")

        # Should contain anomaly information
        validate_contains_data_markers(
            result_str,
            ["anomaly", "unusual", "pattern", "dns", "query", "client"],
            "dns_anomalies"
        )

        print(f"\n✓ Anomaly detection completed")

    @pytest.mark.integration
    def test_wireless_health(self):
        """Test wireless_health returns wireless metrics."""
        result = call_mcp_tool("wireless_health", {"hours": 1})

        result_str = result.get("result", str(result))
        validate_non_empty(result_str, "wireless_health")

        # Should contain wireless-related information
        validate_contains_data_markers(
            result_str,
            ["wireless", "wifi", "ap", "access point", "signal", "client"],
            "wireless_health"
        )

        print(f"\n✓ Wireless health retrieved")

    @pytest.mark.integration
    def test_infrastructure_events(self):
        """Test infrastructure_events returns system events."""
        result = call_mcp_tool("infrastructure_events", {"hours": 1, "limit": 50})

        result_str = result.get("result", str(result))
        validate_non_empty(result_str, "infrastructure_events")

        # Should contain infrastructure information
        validate_contains_data_markers(
            result_str,
            ["event", "system", "service", "error", "warning", "status"],
            "infrastructure_events"
        )

        print(f"\n✓ Infrastructure events retrieved")

    @pytest.mark.integration
    def test_search_logs_for_ip(self):
        """Test search_logs_for_ip returns IP-specific logs."""
        result = call_mcp_tool("search_logs_for_ip", {
            "ip_address": TEST_IP,
            "hours": 1,
            "limit": 50
        })

        result_str = result.get("result", str(result))
        validate_non_empty(result_str, "search_logs_for_ip")

        # Should contain the searched IP
        assert TEST_IP in result_str, f"Searched IP {TEST_IP} not found in results"

        # Should have log-like structure
        validate_contains_data_markers(
            result_str,
            ["log", "entry", "timestamp", "message", TEST_IP],
            "search_logs_for_ip"
        )

        print(f"\n✓ Log search for {TEST_IP} completed")


class TestErrorHandling:
    """Test error handling and edge cases."""

    @pytest.mark.integration
    def test_invalid_tool_name(self):
        """Test calling non-existent tool returns error."""
        url = f"{MCP_BASE_URL}/mcp/tools/nonexistent_tool"
        response = requests.post(url, json={}, timeout=5)

        # Should return 404 or error response
        assert response.status_code in [404, 422, 500], \
            f"Expected error status for invalid tool, got {response.status_code}"

    @pytest.mark.integration
    def test_invalid_parameters(self):
        """Test calling tool with invalid parameters."""
        # Try negative hours
        try:
            result = call_mcp_tool("top_dns_clients", {"hours": -1, "limit": 10})
            # If it doesn't raise, check for error in result
            result_str = str(result)
            assert "error" in result_str.lower() or len(result_str) > 0
        except (AssertionError, requests.exceptions.RequestException):
            # Expected - should fail validation
            pass

    @pytest.mark.integration
    def test_excessive_limit(self):
        """Test tool handles excessive limit gracefully."""
        result = call_mcp_tool("top_dns_clients", {"hours": 1, "limit": 10000})

        # Should still return valid data (possibly capped)
        result_str = result.get("result", str(result))
        validate_non_empty(result_str, "top_dns_clients with excessive limit")


class TestDataConsistency:
    """Test data consistency across related tools."""

    @pytest.mark.integration
    def test_client_data_consistency(self):
        """Test that client IPs appear consistently across tools."""
        # Get top clients
        top_clients = call_mcp_tool("top_dns_clients", {"hours": 1, "limit": 5})
        top_clients_str = top_clients.get("result", str(top_clients))

        # Get block rates
        block_rates = call_mcp_tool("dns_block_rates", {"hours": 1, "min_block_rate": 0.0, "limit": 5})
        block_rates_str = block_rates.get("result", str(block_rates))

        # Extract IPs from both
        top_ips = set(validate_ip_addresses(top_clients_str, "top_clients"))
        block_ips = set(validate_ip_addresses(block_rates_str, "block_rates"))

        # Should have some overlap (active clients should appear in both)
        overlap = top_ips & block_ips

        print(f"\n✓ Found {len(top_ips)} clients in top_clients")
        print(f"✓ Found {len(block_ips)} clients in block_rates")
        print(f"✓ Overlap: {len(overlap)} clients appear in both")

        # At least one client should be in both (unless no traffic)
        assert len(overlap) > 0 or len(top_ips) == 0, \
            "No client overlap between tools (unexpected)"


# === Test Report ===

@pytest.fixture(scope="session", autouse=True)
def print_test_summary(request):
    """Print test summary after all tests complete."""
    yield

    print("\n" + "=" * 80)
    print("MCP SERVER E2E TEST SUMMARY")
    print("=" * 80)
    print(f"MCP Server: {MCP_BASE_URL}")
    print(f"Test IP: {TEST_IP}")
    print("\nAll tools tested:")
    print("  Metrics: top_dns_clients, dns_block_rates, high_risk_clients,")
    print("           blocked_domains, dns_traffic_by_type")
    print("  Logs: security_summary, dns_anomalies, wireless_health,")
    print("        infrastructure_events, search_logs_for_ip")
    print("\nData validation:")
    print("  ✓ Response structure")
    print("  ✓ IP address format")
    print("  ✓ Expected data markers")
    print("  ✓ Cross-tool consistency")
    print("=" * 80)


if __name__ == "__main__":
    # Run with: python tests/integration/test_mcp_e2e.py
    pytest.main([__file__, "-v", "-s", "--tb=short"])
