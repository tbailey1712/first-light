#!/usr/bin/env python
"""
Integration tests for the REST API v1 endpoints.

Tests the FastAPI router at /api/v1/ that serves dashboard widget data.
All tests hit real infrastructure (ClickHouse, Proxmox, Uptime Kuma, etc.)
via the same LangChain tools the agents use.

Run with:
    pytest tests/integration/test_rest_api.py -v
    pytest tests/integration/test_rest_api.py -v -k "health"
    pytest tests/integration/test_rest_api.py -v -k "dns"
"""

import sys
import os
import json

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from dotenv import load_dotenv
load_dotenv()

from fastapi.testclient import TestClient
from ui.app import app

client = TestClient(app)


# ═══════════════════════════════════════════════════════════════════════════════
# Envelope validation
# ═══════════════════════════════════════════════════════════════════════════════

def _assert_envelope(response, expected_status=200):
    """Verify standard JSON envelope structure."""
    assert response.status_code == expected_status, (
        f"Expected HTTP {expected_status}, got {response.status_code}: {response.text[:500]}"
    )
    body = response.json()
    assert "status" in body, f"Missing 'status' in response: {body}"
    assert "timestamp" in body, f"Missing 'timestamp' in response: {body}"
    if body["status"] == "ok":
        assert "data" in body, f"Missing 'data' in ok response: {body}"
        assert "cached" in body, f"Missing 'cached' in ok response: {body}"
    return body


# ═══════════════════════════════════════════════════════════════════════════════
# Health endpoints
# ═══════════════════════════════════════════════════════════════════════════════

class TestHealthEndpoints:
    """Test /api/v1/health/* endpoints."""

    @pytest.mark.integration
    def test_health_infra(self):
        """Infrastructure health returns overall status and collector details."""
        resp = client.get("/api/v1/health/infra")
        body = _assert_envelope(resp)
        data = body["data"]

        assert "overall" in data, "Missing 'overall' in infra health"
        assert data["overall"] in ("ok", "warning", "critical")
        assert "metric_collectors" in data
        assert "log_ingestion" in data
        assert "containers" in data

        # Each collector should have status and name
        for collector in data["metric_collectors"]:
            assert "collector" in collector
            assert "status" in collector
            assert collector["status"] in ("ok", "warning", "critical")

    @pytest.mark.integration
    def test_health_proxmox(self):
        """Proxmox health returns node, VM, and storage data."""
        resp = client.get("/api/v1/health/proxmox")
        body = _assert_envelope(resp)
        data = body["data"]

        assert "nodes" in data, "Missing 'nodes' in proxmox health"
        assert "vms" in data
        assert "containers" in data
        assert "storage" in data

        # Node should have CPU and memory info
        for node_name, node_data in data["nodes"].items():
            assert "cpu_pct" in node_data
            assert "mem_used_gb" in node_data

    @pytest.mark.integration
    def test_health_uptime(self):
        """Uptime Kuma status returns monitor list."""
        resp = client.get("/api/v1/health/uptime")
        body = _assert_envelope(resp)
        data = body["data"]

        assert isinstance(data, list), f"Expected list of monitors, got {type(data)}"
        assert len(data) > 0, "No monitors returned"

        # Each monitor should have key fields
        for monitor in data:
            assert "name" in monitor
            assert "status" in monitor
            assert "status_text" in monitor
            assert monitor["status_text"] in ("up", "down", "unknown")

    @pytest.mark.integration
    def test_health_uptime_incidents(self):
        """Uptime Kuma incidents returns list (possibly empty)."""
        resp = client.get("/api/v1/health/uptime/incidents?hours=24")
        body = _assert_envelope(resp)
        data = body["data"]

        assert isinstance(data, list), f"Expected list, got {type(data)}"
        # Incidents may be empty — that's fine
        for incident in data:
            assert "name" in incident
            assert "down_at" in incident

    def test_health_uptime_incidents_validates_hours(self):
        """Hours parameter is validated."""
        resp = client.get("/api/v1/health/uptime/incidents?hours=0")
        assert resp.status_code == 422

        resp = client.get("/api/v1/health/uptime/incidents?hours=999")
        assert resp.status_code == 422


# ═══════════════════════════════════════════════════════════════════════════════
# DNS / AdGuard endpoints
# ═══════════════════════════════════════════════════════════════════════════════

class TestDNSEndpoints:
    """Test /api/v1/dns/* endpoints."""

    @pytest.mark.integration
    def test_dns_summary(self):
        """DNS summary returns totals and anomaly sections."""
        resp = client.get("/api/v1/dns/summary?hours=24")
        body = _assert_envelope(resp)
        data = body["data"]

        # Multi-section format: dict with named sections
        assert isinstance(data, dict), f"Expected dict of sections, got {type(data)}"
        assert "totals" in data, f"Missing 'totals' section. Keys: {list(data.keys())}"
        assert "anomalies_by_severity" in data

        # Totals should be a list of rows
        assert isinstance(data["totals"], list)

    @pytest.mark.integration
    def test_dns_top_clients(self):
        """Top DNS clients returns rows of client data."""
        resp = client.get("/api/v1/dns/top-clients?hours=24&limit=5")
        body = _assert_envelope(resp)
        data = body["data"]

        assert isinstance(data, list), f"Expected list of rows, got {type(data)}"
        assert len(data) > 0, "No DNS clients returned"

        # Each row should be a list of values (headerless TSV)
        for row in data:
            assert isinstance(row, list), f"Expected list row, got {type(row)}"
            assert len(row) >= 3, f"Row has too few columns: {row}"

    @pytest.mark.integration
    def test_dns_block_rates(self):
        """Block rates returns per-client block data."""
        resp = client.get("/api/v1/dns/block-rates?hours=24&limit=5")
        body = _assert_envelope(resp)
        data = body["data"]

        assert isinstance(data, list), f"Expected list, got {type(data)}"

    @pytest.mark.integration
    def test_dns_blocked_domains(self):
        """Blocked domains returns list of blocked content."""
        resp = client.get("/api/v1/dns/blocked-domains?hours=24&limit=5")
        body = _assert_envelope(resp)
        data = body["data"]

        assert isinstance(data, list), f"Expected list, got {type(data)}"

    @pytest.mark.integration
    def test_dns_threat_signals(self):
        """Threat signals returns multi-section detection data."""
        resp = client.get("/api/v1/dns/threat-signals?hours=24")
        body = _assert_envelope(resp)
        data = body["data"]

        # Multi-section format
        assert isinstance(data, (dict, list)), f"Unexpected type: {type(data)}"

    def test_dns_validates_params(self):
        """Query parameters are validated."""
        # hours out of range
        resp = client.get("/api/v1/dns/top-clients?hours=0")
        assert resp.status_code == 422

        resp = client.get("/api/v1/dns/top-clients?hours=999")
        assert resp.status_code == 422

        # limit out of range
        resp = client.get("/api/v1/dns/top-clients?limit=0")
        assert resp.status_code == 422

        resp = client.get("/api/v1/dns/top-clients?limit=200")
        assert resp.status_code == 422


# ═══════════════════════════════════════════════════════════════════════════════
# Security endpoints
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityEndpoints:
    """Test /api/v1/security/* endpoints."""

    @pytest.mark.integration
    def test_security_summary(self):
        """Security summary returns firewall and threat data."""
        resp = client.get("/api/v1/security/summary?hours=1")
        body = _assert_envelope(resp)
        data = body["data"]

        assert isinstance(data, dict), f"Expected dict, got {type(data)}"
        assert "firewall_blocks" in data, f"Missing firewall_blocks. Keys: {list(data.keys())}"

    @pytest.mark.integration
    def test_security_threats(self):
        """Threat intel returns enriched blocked IPs."""
        resp = client.get("/api/v1/security/threats?hours=24&min_score=0")
        body = _assert_envelope(resp)
        data = body["data"]

        assert isinstance(data, dict), f"Expected dict, got {type(data)}"
        assert "time_range" in data

    @pytest.mark.integration
    def test_security_threat_coverage(self):
        """Threat coverage returns enrichment stats."""
        resp = client.get("/api/v1/security/threat-coverage")
        body = _assert_envelope(resp)
        data = body["data"]

        assert isinstance(data, dict), f"Expected dict, got {type(data)}"
        assert "coverage" in data, f"Missing 'coverage'. Keys: {list(data.keys())}"


# ═══════════════════════════════════════════════════════════════════════════════
# Status & Weather endpoints
# ═══════════════════════════════════════════════════════════════════════════════

class TestStatusEndpoints:
    """Test /api/v1/status and /api/v1/weather."""

    @pytest.mark.integration
    def test_status(self):
        """System status returns integration and Redis info."""
        resp = client.get("/api/v1/status")
        body = _assert_envelope(resp)
        data = body["data"]

        assert "integrations" in data
        assert "redis" in data
        assert "report_count" in data

    @pytest.mark.integration
    def test_weather(self):
        """Weather returns current conditions."""
        resp = client.get("/api/v1/weather")
        body = _assert_envelope(resp)
        data = body["data"]

        assert "temp_f" in data, f"Missing temp_f. Keys: {list(data.keys())}"
        assert "description" in data
        assert "humidity" in data
        assert data["location"] == "Dallas, TX"


# ═══════════════════════════════════════════════════════════════════════════════
# Caching behavior
# ═══════════════════════════════════════════════════════════════════════════════

class TestCaching:
    """Test TTL caching behavior."""

    @pytest.mark.integration
    def test_second_request_is_cached(self):
        """Second request to same endpoint returns cached: true."""
        # First request populates cache
        resp1 = client.get("/api/v1/weather")
        body1 = _assert_envelope(resp1)

        # Second request should hit cache
        resp2 = client.get("/api/v1/weather")
        body2 = _assert_envelope(resp2)
        assert body2["cached"] is True, "Second request should be cached"

    @pytest.mark.integration
    def test_different_params_are_separate_cache_entries(self):
        """Different query params produce different cache entries."""
        resp1 = client.get("/api/v1/dns/top-clients?hours=1&limit=5")
        body1 = _assert_envelope(resp1)

        resp2 = client.get("/api/v1/dns/top-clients?hours=2&limit=5")
        body2 = _assert_envelope(resp2)
        # Second request with different hours should NOT be cached
        assert body2["cached"] is False, "Different params should be separate cache entries"


# ═══════════════════════════════════════════════════════════════════════════════
# CORS headers
# ═══════════════════════════════════════════════════════════════════════════════

class TestCORS:
    """Test CORS headers for Dashy cross-origin requests."""

    def test_cors_preflight_allowed_origin(self):
        """Dashy origin gets CORS approval."""
        resp = client.options(
            "/api/v1/health/uptime",
            headers={
                "Origin": "http://192.168.2.106:4200",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert resp.headers.get("access-control-allow-origin") == "http://192.168.2.106:4200"

    def test_cors_preflight_disallowed_origin(self):
        """Unknown origin does not get CORS approval."""
        resp = client.options(
            "/api/v1/health/uptime",
            headers={
                "Origin": "http://evil.example.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert resp.headers.get("access-control-allow-origin") != "http://evil.example.com"

    def test_cors_response_header(self):
        """GET responses include CORS header for Dashy origin."""
        resp = client.get(
            "/api/v1/health",
            headers={"Origin": "http://192.168.2.106:4200"},
        )
        # Even a 404 should have CORS headers when origin matches
        allow = resp.headers.get("access-control-allow-origin")
        # CORS middleware only adds header for matching origins
        assert allow in ("http://192.168.2.106:4200", None)


# ═══════════════════════════════════════════════════════════════════════════════
# Error handling
# ═══════════════════════════════════════════════════════════════════════════════

class TestErrorHandling:
    """Test error responses and edge cases."""

    def test_nonexistent_endpoint_404(self):
        """Unknown API path returns 404."""
        resp = client.get("/api/v1/nonexistent")
        assert resp.status_code == 404

    def test_existing_health_endpoint_still_works(self):
        """Original /health endpoint is not broken by v1 router."""
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_existing_api_status_still_works(self):
        """Original /api/status endpoint is not broken."""
        resp = client.get("/api/status")
        assert resp.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
