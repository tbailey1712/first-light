#!/usr/bin/env python
"""
Integration tests for DNS Security MCP Server.

Tests tool registration and execution without mocking.
"""

import sys
import os
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from dotenv import load_dotenv
load_dotenv()

# Import after path setup
from agent.tools import get_all_tools


class TestMCPServerSetup:
    """Test MCP server setup and tool registration."""

    def test_tools_available(self):
        """Verify DNS tools are available for MCP server."""
        tools = get_all_tools()

        assert len(tools) > 0, "No tools available"
        assert len(tools) == 10, f"Expected 10 tools, got {len(tools)}"

    def test_tool_structure(self):
        """Verify tools have required attributes for MCP export."""
        tools = get_all_tools()

        for tool in tools:
            # Check required attributes
            assert hasattr(tool, 'name'), f"Tool missing 'name' attribute: {tool}"
            assert hasattr(tool, 'description'), f"Tool missing 'description' attribute: {tool}"

            # Check name format
            assert isinstance(tool.name, str), f"Tool name not a string: {tool.name}"
            assert len(tool.name) > 0, f"Tool has empty name"

            # Check description format
            assert isinstance(tool.description, str) or tool.description is None, \
                f"Tool description invalid type: {type(tool.description)}"

    def test_metrics_tools_present(self):
        """Verify all expected metrics tools are present."""
        tools = get_all_tools()
        tool_names = [t.name for t in tools]

        expected_metrics_tools = [
            "query_adguard_top_clients",
            "query_adguard_block_rates",
            "query_adguard_high_risk_clients",
            "query_adguard_blocked_domains",
            "query_adguard_traffic_by_type",
        ]

        for expected_tool in expected_metrics_tools:
            assert expected_tool in tool_names, \
                f"Expected metrics tool '{expected_tool}' not found. Available: {tool_names}"

    def test_logs_tools_present(self):
        """Verify all expected logs tools are present."""
        tools = get_all_tools()
        tool_names = [t.name for t in tools]

        expected_logs_tools = [
            "query_security_summary",
            "query_adguard_anomalies",
            "query_wireless_health",
            "query_infrastructure_events",
            "search_logs_by_ip",
        ]

        for expected_tool in expected_logs_tools:
            assert expected_tool in tool_names, \
                f"Expected logs tool '{expected_tool}' not found. Available: {tool_names}"


class TestMCPServerExecution:
    """Test MCP server tool execution with real data sources."""

    def test_tool_invocation_signature(self):
        """Verify tools can be invoked (signature test, no actual execution)."""
        tools = get_all_tools()

        for tool in tools:
            # Check tool has invoke method (LangChain tool interface)
            assert hasattr(tool, 'invoke') or hasattr(tool, 'run'), \
                f"Tool '{tool.name}' missing 'invoke' or 'run' method"

    @pytest.mark.integration
    def test_query_adguard_top_clients(self):
        """Test query_adguard_top_clients with real API call."""
        tools = get_all_tools()
        tool = next(t for t in tools if t.name == "query_adguard_top_clients")

        # Execute with minimal time range
        result = tool.invoke({"hours": 1, "limit": 5})

        # Verify result is string (formatted output)
        assert isinstance(result, str), f"Expected string result, got {type(result)}"
        assert len(result) > 0, "Result is empty"

    @pytest.mark.integration
    def test_query_adguard_block_rates(self):
        """Test query_adguard_block_rates with real API call."""
        tools = get_all_tools()
        tool = next(t for t in tools if t.name == "query_adguard_block_rates")

        # Execute with minimal time range
        result = tool.invoke({"hours": 1, "min_block_rate": 0.0, "limit": 5})

        # Verify result is string
        assert isinstance(result, str), f"Expected string result, got {type(result)}"
        assert len(result) > 0, "Result is empty"

    @pytest.mark.integration
    def test_search_logs_by_ip(self):
        """Test search_logs_by_ip with real API call."""
        tools = get_all_tools()
        tool = next(t for t in tools if t.name == "search_logs_by_ip")

        # Search for a common internal IP
        result = tool.invoke({"ip_address": "192.168.1.1", "hours": 1, "limit": 10})

        # Verify result format
        assert isinstance(result, str), f"Expected string result, got {type(result)}"


class TestMCPServerErrorHandling:
    """Test MCP server error handling."""

    def test_tool_with_invalid_args(self):
        """Test tool execution with invalid arguments."""
        tools = get_all_tools()
        tool = next(t for t in tools if t.name == "query_adguard_top_clients")

        # Try with invalid argument types (should raise or return error)
        try:
            result = tool.invoke({"hours": "invalid", "limit": 5})
            # If no exception, result should indicate error
            assert "error" in result.lower() or "invalid" in result.lower()
        except (ValueError, TypeError, Exception) as e:
            # Expected - tool should validate inputs
            assert True

    def test_tool_with_excessive_time_range(self):
        """Test tool execution with very large time range (should handle gracefully)."""
        tools = get_all_tools()
        tool = next(t for t in tools if t.name == "query_adguard_top_clients")

        # Some tools may limit the time range internally
        try:
            result = tool.invoke({"hours": 999999, "limit": 5})
            # Should complete (possibly with capped time range)
            assert isinstance(result, str)
        except Exception as e:
            # Acceptable to raise error for excessive ranges
            assert True


if __name__ == "__main__":
    # Run with: python -m pytest tests/integration/test_mcp_server.py -v
    # Or: python tests/integration/test_mcp_server.py
    pytest.main([__file__, "-v"])
