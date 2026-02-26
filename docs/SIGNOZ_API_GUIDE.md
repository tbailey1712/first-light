# SigNoz API Guide - First Light

## API Overview

- **Base URL:** `http://192.168.2.106:8081`
- **Logs Endpoint:** `POST /api/v5/query_range`
- **Authentication:** Header `SIGNOZ-API-KEY: {YOUR_API_KEY}`
- **Version:** v0.112.0 Enterprise Edition

## Getting an API Key

1. Open SigNoz UI: http://192.168.2.106:8081
2. Navigate to **Settings → API Keys**
3. Click **Create New API Key**
4. Give it a name (e.g., "First Light Automation")
5. Copy the key (you won't see it again!)
6. Store in `.env` file as `SIGNOZ_API_KEY=your-key-here`

## Query Logs API

### Endpoint
```
POST http://192.168.2.106:8081/api/v5/query_range
```

### Headers
```
Content-Type: application/json
SIGNOZ-API-KEY: {YOUR_API_KEY}
```

### Payload Structure
```json
{
  "start": 1700733979000,
  "end": 1700737579000,
  "requestType": "raw",
  "variables": {},
  "compositeQuery": {
    "queries": [
      {
        "type": "builder_query",
        "spec": {
          "name": "A",
          "signal": "logs",
          "filter": {
            "expression": "host_name = 'firewall.mcducklabs.com'"
          },
          "order": [
            {
              "key": {"name": "timestamp"},
              "direction": "desc"
            },
            {
              "key": {"name": "id"},
              "direction": "desc"
            }
          ],
          "offset": 0,
          "limit": 10
        }
      }
    ]
  }
}
```

### Filter Expression Syntax

Filters use boolean logic combining attributes:

**Examples:**
- Single condition: `host_name = 'firewall.mcducklabs.com'`
- Multiple conditions: `host_name = 'firewall' AND severity_text = 'ERROR'`
- OR logic: `severity_text = 'ERROR' OR severity_text = 'CRITICAL'`
- LIKE pattern: `body LIKE '%failed%'`
- IN clause: `severity_text IN ('ERROR', 'CRITICAL', 'WARN')`
- NOT: `NOT (host_name = 'ntopng')`

**Attribute Names:**
- Resource attributes: `host_name`, `service_name`, `device_type`
- Log attributes: `pfsense_action`, `pfsense_src_ip`, `network_zone`
- Standard fields: `severity_text`, `body`, `timestamp`

**Note:** Attribute names with dots (`.`) are converted to underscores (`_`) in filter expressions.
- `host.name` → `host_name`
- `pfsense.action` → `pfsense_action`

### Pagination

For large result sets:
```json
{
  "offset": 0,   // Start at record 0
  "limit": 100   // Get 100 records
}
```

Next page:
```json
{
  "offset": 100,  // Skip first 100
  "limit": 100    // Get next 100
}
```

## Example Queries

### Get All Firewall Blocks
```bash
curl -X POST http://192.168.2.106:8081/api/v5/query_range \
  -H 'Content-Type: application/json' \
  -H 'SIGNOZ-API-KEY: your-key-here' \
  -d '{
    "start": '$(date -v-1H +%s)000',
    "end": '$(date +%s)000',
    "requestType": "raw",
    "variables": {},
    "compositeQuery": {
      "queries": [{
        "type": "builder_query",
        "spec": {
          "name": "A",
          "signal": "logs",
          "filter": {
            "expression": "host_name = '\''firewall.mcducklabs.com'\'' AND pfsense_action = '\''block'\''"
          },
          "order": [
            {"key": {"name": "timestamp"}, "direction": "desc"},
            {"key": {"name": "id"}, "direction": "desc"}
          ],
          "offset": 0,
          "limit": 10
        }
      }]
    }
  }'
```

### Get Security Events (Blocks OR Errors)
```json
{
  "filter": {
    "expression": "pfsense_action = 'block' OR severity_text IN ('ERROR', 'CRITICAL', 'WARN')"
  }
}
```

### Get Logs from Specific Device
```json
{
  "filter": {
    "expression": "host_name = 'nas.mcducklabs.com'"
  }
}
```

### Search Log Body
```json
{
  "filter": {
    "expression": "body LIKE '%failed%' AND body LIKE '%ssh%'"
  }
}
```

## Alerts API

### Create Alert Rule
```
POST /api/v1/rules
```

**Payload:** (To be documented after testing)

### List Alert Rules
```
GET /api/v1/rules
```

## Dashboards API

### Create Dashboard
```
POST /api/v1/dashboards
```

### List Dashboards
```
GET /api/v1/dashboards
```

## Next Steps

1. **Get API Key** - Navigate to Settings → API Keys in SigNoz UI
2. **Test Query** - Run example query to verify access
3. **Verify Attributes** - Check actual attribute names in response
4. **Build Automation** - Create scripts for saved views, alerts, dashboards

## References

- [SigNoz Logs API Documentation](https://signoz.io/docs/logs-management/logs-api/overview/)
- [Search Logs API](https://signoz.io/docs/logs-management/logs-api/search-logs/)
- [Payload Model](https://signoz.io/docs/logs-management/logs-api/payload-model/)
- [SigNoz API Reference](https://signoz.io/api-reference/)
