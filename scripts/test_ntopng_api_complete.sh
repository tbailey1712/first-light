#!/bin/bash
# Comprehensive test of all ntopng API tools
# Verified against Swagger spec

set -e

HOST="192.168.1.5"
PORT="3000"
USER="firstlight"
PASS="f1rst"
IFID="3"

echo "======================================================================="
echo "Testing All ntopng REST API Endpoints"
echo "======================================================================="
echo "Host: $HOST:$PORT"
echo "Interface ID: $IFID"
echo ""

# Helper function to test endpoint
test_endpoint() {
    local name="$1"
    local url="$2"
    echo ""
    echo "[$name]"
    echo "URL: $url"

    response=$(curl -s -u "$USER:$PASS" "$url" --max-time 10)
    rc_str=$(echo "$response" | python3 -c "import json, sys; data=json.load(sys.stdin); print(data.get('rc_str', 'N/A'))" 2>/dev/null || echo "ERROR")

    if [ "$rc_str" = "OK" ]; then
        echo "✅ Status: OK"
        # Try to show a preview of the data
        echo "$response" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    rsp = data.get('rsp', {})
    if isinstance(rsp, dict):
        if 'totalRows' in rsp:
            print(f\"  Total rows: {rsp.get('totalRows', 0)}\")
        if 'data' in rsp and isinstance(rsp['data'], list):
            print(f\"  Returned: {len(rsp['data'])} items\")
    elif isinstance(rsp, list):
        print(f\"  Returned: {len(rsp)} items\")
except:
    pass
" 2>/dev/null
    elif [ "$rc_str" = "N/A" ]; then
        echo "⚠️  Response format unexpected (no rc_str)"
    else
        echo "❌ Status: $rc_str"
        echo "$response" | head -3
    fi
}

# Test 1: Interfaces
test_endpoint \
    "query_ntopng_interfaces" \
    "http://$HOST:$PORT/lua/rest/v2/get/ntopng/interfaces.lua"

# Test 2: Interface Stats
test_endpoint \
    "query_ntopng_interface_stats" \
    "http://$HOST:$PORT/lua/rest/v2/get/interface/data.lua?ifid=$IFID"

# Test 3: Active Hosts (replaces top_talkers)
test_endpoint \
    "query_ntopng_active_hosts" \
    "http://$HOST:$PORT/lua/rest/v2/get/host/active.lua?ifid=$IFID&currentPage=1&perPage=20&sortColumn=bytes&sortOrder=desc"

# Test 4: Active Flows
test_endpoint \
    "query_ntopng_active_flows" \
    "http://$HOST:$PORT/lua/rest/v2/get/flow/active.lua?ifid=$IFID&currentPage=1&perPage=20&sortColumn=bytes&sortOrder=desc"

# Test 5: Alerts (replaces list_engaged)
test_endpoint \
    "query_ntopng_alerts" \
    "http://$HOST:$PORT/lua/rest/v2/get/all/alert/list.lua?ifid=$IFID&currentPage=1&perPage=50"

# Test 6: L7 Protocol Counters (fixed endpoint)
test_endpoint \
    "query_ntopng_l7_protocols" \
    "http://$HOST:$PORT/lua/rest/v2/get/flow/l7/counters.lua?ifid=$IFID"

# Test 7: ARP Table (NEW)
test_endpoint \
    "query_ntopng_arp_table" \
    "http://$HOST:$PORT/lua/rest/v2/get/interface/arp.lua?ifid=$IFID"

# Test 8: Host Details
# Get a host IP from active hosts first
HOST_IP=$(curl -s -u "$USER:$PASS" "http://$HOST:$PORT/lua/rest/v2/get/host/active.lua?ifid=$IFID&perPage=1" | \
    python3 -c "import json, sys; d=json.load(sys.stdin); print(d['rsp']['data'][0]['ip'])" 2>/dev/null || echo "192.168.1.1")

test_endpoint \
    "query_ntopng_host_details" \
    "http://$HOST:$PORT/lua/rest/v2/get/host/data.lua?host=$HOST_IP&ifid=$IFID"

# Test 9: Host L7 Stats (NEW)
test_endpoint \
    "query_ntopng_host_l7_stats" \
    "http://$HOST:$PORT/lua/rest/v2/get/host/l7/stats.lua?host=$HOST_IP&ifid=$IFID"

echo ""
echo "======================================================================="
echo "Test Complete!"
echo "======================================================================="
