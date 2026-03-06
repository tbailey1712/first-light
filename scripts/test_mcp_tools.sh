#!/bin/bash
# Manual MCP Server Tool Test Script
#
# Tests all 10 MCP tools and displays actual output
#
# Usage:
#   ./scripts/test_mcp_tools.sh
#
# Requirements:
#   - MCP server running: docker-compose up -d mcp-server
#   - curl and jq installed

set -e

MCP_URL="http://localhost:8082"
TEST_IP="192.168.1.1"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "================================================================================"
echo "MCP SERVER TOOL TEST"
echo "================================================================================"
echo "MCP URL: $MCP_URL"
echo "Test IP: $TEST_IP"
echo ""

# Check server health
echo -e "${BLUE}Checking MCP server health...${NC}"
if curl -s -f "$MCP_URL/health" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ MCP server is running${NC}"
else
    echo -e "${RED}✗ MCP server is not responding${NC}"
    echo "Start it with: docker-compose up -d mcp-server"
    exit 1
fi

echo ""

# Test function
test_tool() {
    local tool_name=$1
    local params=$2
    local description=$3

    echo "────────────────────────────────────────────────────────────────────────────────"
    echo -e "${YELLOW}Testing: ${tool_name}${NC}"
    echo "Description: $description"
    echo "Parameters: $params"
    echo ""

    response=$(curl -s -X POST "$MCP_URL/mcp/tools/$tool_name" \
        -H "Content-Type: application/json" \
        -d "$params" || echo '{"error": "Request failed"}')

    if echo "$response" | grep -q '"error"'; then
        echo -e "${RED}✗ Error:${NC}"
        echo "$response" | jq -r '.error // .detail // .' 2>/dev/null || echo "$response"
    else
        echo -e "${GREEN}✓ Success${NC}"
        echo ""
        # Try to extract result field, or show full response
        result=$(echo "$response" | jq -r '.result // .' 2>/dev/null | head -50)
        echo "$result"

        # Show count if result is long
        line_count=$(echo "$result" | wc -l)
        if [ "$line_count" -gt 50 ]; then
            echo ""
            echo "... (output truncated, showing first 50 lines of $line_count total)"
        fi
    fi
    echo ""
}

# === METRICS TOOLS ===

echo "================================================================================"
echo "METRICS TOOLS (VictoriaMetrics/PromQL)"
echo "================================================================================"
echo ""

test_tool "top_dns_clients" \
    '{"hours": 24, "limit": 10}' \
    "Top DNS clients by query volume"

test_tool "dns_block_rates" \
    '{"hours": 24, "min_block_rate": 0.0, "limit": 10}' \
    "DNS block rates per client"

test_tool "high_risk_clients" \
    '{"hours": 24, "min_risk_score": 5.0, "limit": 10}' \
    "High-risk clients with suspicious activity"

test_tool "blocked_domains" \
    '{"hours": 24, "limit": 20}' \
    "Most frequently blocked domains"

test_tool "dns_traffic_by_type" \
    '{"hours": 24}' \
    "DNS query volume breakdown by type"

# === LOGS TOOLS ===

echo "================================================================================"
echo "LOGS TOOLS (Loki/LogQL)"
echo "================================================================================"
echo ""

test_tool "security_summary" \
    '{"hours": 1}' \
    "Security threats and blocks summary"

test_tool "dns_anomalies" \
    '{"hours": 1, "limit": 10}' \
    "DNS anomalies and unusual patterns"

test_tool "wireless_health" \
    '{"hours": 1}' \
    "Wireless network health summary"

test_tool "infrastructure_events" \
    '{"hours": 1, "limit": 20}' \
    "Infrastructure events and alerts"

test_tool "search_logs_for_ip" \
    "{\"ip_address\": \"$TEST_IP\", \"hours\": 1, \"limit\": 20}" \
    "Search logs for specific IP address"

# === SUMMARY ===

echo "================================================================================"
echo "TEST COMPLETE"
echo "================================================================================"
echo -e "${GREEN}✓ All 10 tools tested${NC}"
echo ""
echo "Tools tested:"
echo "  Metrics: top_dns_clients, dns_block_rates, high_risk_clients,"
echo "           blocked_domains, dns_traffic_by_type"
echo "  Logs: security_summary, dns_anomalies, wireless_health,"
echo "        infrastructure_events, search_logs_for_ip"
echo ""
echo "To run automated validation tests:"
echo "  pytest tests/integration/test_mcp_e2e.py -v"
echo ""
echo "To access API docs:"
echo "  open http://localhost:8082/docs"
echo "================================================================================"
