# ntopng Integration Setup

## Overview

First Light integrates with ntopng for network flow analysis via two methods:
1. **Log parsing** - Parse ntopng syslog alerts for security events (✅ **WORKING - 89.5% success rate**)
2. **REST API** - Query flow data, top talkers, and alerts programmatically (⚠️ **NEEDS CONFIGURATION**)

## Current Status

### ✅ Log Parsing (WORKING)

ntopng sends syslog alerts to the OTel collector, which parses and extracts:
- Alert name and severity
- Interface and timestamp
- Flow source and destination (host, VLAN, port)
- Network direction classification
- Security event categorization

**Success Rate**: 89.5% (10.5% failures due to hostname truncation in ntopng logs)

**Sample Parsed Flow**:
```
Alert: Known Proto on Non Std Port
Flow: 154.29.148.94@4:30303 -> vldtr@4:9000
  - Source: 154.29.148.94 (VLAN 4, port 30303)
  - Destination: vldtr (VLAN 4, port 9000)
Direction: Internal
```

### ⚠️ REST API (NEEDS CONFIGURATION)

7 API tools created in `agent/tools/ntopng.py`:
1. `query_ntopng_interfaces()` - List monitored interfaces
2. `query_ntopng_top_talkers()` - Get top bandwidth users
3. `query_ntopng_interface_stats()` - Detailed interface statistics
4. `query_ntopng_active_alerts()` - Currently active alerts
5. `query_ntopng_host_details()` - Host traffic details
6. `query_ntopng_flow_summary()` - Active flow summary
7. `query_ntopng_l7_protocols()` - Application protocol breakdown

## Setup Instructions

### 1. Get ntopng Credentials

ntopng is running on `192.168.1.5:3000` (version 6.7.260217).

**Default credentials** (if unchanged):
- Username: `admin`
- Password: `admin`

**To check/reset ntopng password**:
- SSH to ntopng host (192.168.1.5)
- Check ntopng config: `/etc/ntopng/ntopng.conf`
- Or reset via ntopng CLI/web interface

### 2. Configure .env

Add these variables to `/opt/first-light/.env`:

```bash
# ntopng REST API
NTOPNG_HOST=192.168.1.5
NTOPNG_PORT=3000
NTOPNG_USERNAME=admin
NTOPNG_PASSWORD=your_actual_password
```

### 3. Test the API

Run the test script:

```bash
cd /opt/first-light
python3 scripts/test_ntopng_api.py
```

Expected output:
```
============================================================
Testing ntopng API
============================================================
Host: 192.168.1.5:3000
Username: admin

1. Testing query_ntopng_interfaces()...
   ✅ Success: Found interface data

2. Testing query_ntopng_top_talkers()...
   ✅ Success: Retrieved top talkers

[... etc ...]

✅ All ntopng API tests completed successfully!
============================================================
```

### 4. Common Issues

**Issue**: `Error: HTTP 302` or redirect to login page
- **Cause**: Invalid credentials
- **Fix**: Verify username/password in .env match ntopng settings

**Issue**: `Error: Request timed out after 10 seconds`
- **Cause**: ntopng host unreachable or wrong IP/port
- **Fix**: Verify ntopng is running on 192.168.1.5:3000

**Issue**: `Error: HTTP 404`
- **Cause**: REST API endpoint not available (Community vs Enterprise edition)
- **Fix**: Check ntopng version/edition - some endpoints require Enterprise

## API Tool Usage

Once configured, the AI agent can use these tools to:

- **Identify top bandwidth users**: "Show me the top 10 bandwidth users right now"
- **Analyze flow patterns**: "What protocols are using the most bandwidth on VLAN 4?"
- **Investigate alerts**: "Are there any active ntopng alerts?"
- **Host investigation**: "Show me all traffic for 192.168.1.100"
- **Security analysis**: "Which external IPs are connecting to my validator?"

## Log Parser Details

The ntopng log parser (`transform/ntopng` in OTel config) extracts:

**Extracted Fields**:
- `ntopng.timestamp` - ISO timestamp from log
- `ntopng.interface` - Network interface (e.g., eth0)
- `ntopng.severity` - Warning, Error, Critical, Info
- `ntopng.type` - Flow or Host alert
- `ntopng.alert_name` - Alert type (e.g., "Known Proto on Non Std Port")
- `ntopng.flow.src_host` - Source hostname/IP
- `ntopng.flow.src_vlan` - Source VLAN ID
- `ntopng.flow.src_port` - Source port
- `ntopng.flow.dst_host` - Destination hostname/IP
- `ntopng.flow.dst_vlan` - Destination VLAN ID
- `ntopng.flow.dst_port` - Destination port
- `ntopng.description` - Full alert description
- `security.severity` - Normalized severity (critical/high/warning/info)
- `security.event` - Set to "true" for high-priority security alerts
- `security.category` - Categorization (e.g., "network_threat")
- `network.direction` - inbound/outbound/internal

**Known Limitation**: 10.5% of logs have truncated hostnames (ntopng limitation) which prevents parsing. These appear as `hostname…:port` instead of `hostname@vlan:port`.

## Next Steps

1. ✅ Configure ntopng API credentials in .env
2. ✅ Run test script to verify API access
3. ✅ Integrate API tools with AI agent graph
4. ✅ Create agent prompts that leverage both logs and API data
5. Optional: Configure ntopng to reduce hostname truncation (if possible)

## Files

- `agent/tools/ntopng.py` - 7 REST API tools
- `signoz/otel-ntopng-parser.yaml` - Standalone parser config
- `signoz/otel-collector-config.yaml` - Active parser (transform/ntopng section)
- `scripts/test_ntopng_api.py` - API test script
- `docs/NTOPNG_SETUP.md` - This file
