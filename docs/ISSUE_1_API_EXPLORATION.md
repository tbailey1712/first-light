# Issue #1: SigNoz API Exploration

## API Status

### Version Check ✅
```bash
curl http://192.168.2.106:8081/api/v1/version
```
```json
{
  "version": "v0.112.0",
  "ee": "Y",
  "setupCompleted": true
}
```

**Result:** SigNoz v0.112.0 Enterprise Edition is running and accessible.

### Logs API ❌
The `/api/v1/logs` endpoint returns HTML (the SigNoz UI) instead of JSON, indicating:
- May need authentication/API key
- May need different endpoint path
- May require using the query service API

## Next Steps

### Option 1: Use SigNoz UI (Recommended for Phase 1.5)
Since Phase 1.5 is focused on making data useful quickly, we should:
1. Create saved views through the SigNoz UI manually
2. Create alerts through the SigNoz UI
3. Build dashboard through the SigNoz UI
4. Export configurations for backup/documentation

**Pros:**
- Faster to implement
- Visual feedback while building
- Can test immediately
- No API authentication issues

**Cons:**
- Less automatable
- Harder to version control
- Can't script bulk operations

### Option 2: Investigate SigNoz API Further
Research needed:
- Check if API key needed (Settings → API Keys in UI)
- Find correct query service endpoint (may be `/api/v3/query` or similar)
- Review SigNoz API documentation
- Check MCP server implementation for examples

## Attribute Verification Plan

Since API query isn't working yet, verify attributes by:
1. Open SigNoz UI: http://192.168.2.106:8081
2. Go to Logs Explorer
3. Click on a recent log to expand details
4. Document all visible attributes in the "Attributes" tab
5. Take screenshot for reference

## Expected Attributes (To Verify)

### Resource Attributes
- [  ] `host.name`
- [  ] `service.name`
- [  ] `device.type`
- [  ] `deployment.environment`

### Log Attributes
- [  ] `pfsense.action`
- [  ] `pfsense.direction`
- [  ] `pfsense.interface`
- [  ] `pfsense.protocol`
- [  ] `pfsense.src_ip`
- [  ] `pfsense.dst_ip`
- [  ] `pfsense.src_port`
- [  ] `pfsense.dst_port`
- [  ] `network.zone`
- [  ] `network.vlan`

### Standard Fields
- [  ] `severity_text`
- [  ] `body`
- [  ] `timestamp`

## Decision

**For Phase 1.5, proceed with UI-based configuration.** This aligns with the plan's goal of getting results quickly without over-engineering. API automation can be Phase 2 or 3.

## Action Items

1. ✅ Verify SigNoz is accessible
2. ⏭️ Open SigNoz UI and verify attributes exist
3. ⏭️ Document actual attribute structure from UI
4. ⏭️ Proceed to Issue #2 (notification channel)
5. ⏭️ Proceed to Issue #3 (saved views via UI)
