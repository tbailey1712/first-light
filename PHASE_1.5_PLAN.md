# First Light — Claude Code Execution Plan
## Phase 1.5: Make the Data Useful

**Date:** February 25, 2026
**Objective:** Transform raw log visibility into actionable views, alerts, and a security dashboard in SigNoz.
**Scope:** SigNoz configuration only. No new services, no new containers, no code beyond API calls and config.

---

## Context

First Light MVP is operational. rsyslog is collecting logs from 10+ devices across 4 VLANs and fanning out to SigNoz and CrowdSec. The OpenTelemetry Collector is enriching logs with structured attributes. ~16,000+ logs/day are flowing.

**The problem:** All the data is there but there's no way to see what matters without manually scrolling thousands of log lines in the SigNoz Logs Explorer.

**The fix:** Saved views, alert rules, and one dashboard. All configured through the SigNoz API or UI.

---

## Available Data Attributes

These attributes are already being set by the OTel Collector enrichment pipeline. Use these for filtering, grouping, and aggregation.

### Resource Attributes (fast filters)
- `host.name` — Device hostname (firewall.mcducklabs.com, nas.mcducklabs.com, pve.mcducklabs.com, ntopng, docker.mcducklabs.com, adguard, UniFiSecondFloorBack, UniFiFirstFloorFront)
- `service.name` — Service/application name
- `device.type` — Device classification (firewall, nas, hypervisor, access-point, monitoring, dns)
- `deployment.environment` — Always "production"

### Log Attributes (detailed filters)
- `pfsense.action` — block, pass
- `pfsense.direction` — in, out
- `pfsense.interface` — Physical interface name
- `pfsense.protocol` — tcp, udp, icmp, etc.
- `pfsense.src_ip` — Source IP address
- `pfsense.dest_ip` — Destination IP address
- `pfsense.src_port` — Source port
- `pfsense.dest_port` — Destination port
- `network.zone` — edge, core, compute, storage
- `network.vlan` — trusted, iot, guest

### Standard Fields
- `severity_text` — Log level (INFO, WARN, ERROR, etc.)
- `body` — Raw log message text
- `timestamp` — Log timestamp

---

## SigNoz Access

- **UI:** http://192.168.2.106:8081
- **API Base:** http://192.168.2.106:8081/api/v1 (or internal http://signoz:8080 from within Docker network)
- **API Key:** Check Settings → Ingestion in the SigNoz UI. Create one if it doesn't exist.
- **Logs API docs:** https://signoz.io/docs/logs-management/logs-api/overview/
- **Metrics API docs:** https://signoz.io/docs/metrics-management/query-range-api/
- **Dashboard API:** Check https://signoz.io/api-reference/ for dashboard CRUD endpoints

---

## Task Breakdown

See GitHub issues for detailed task tracking:
- Issue #1: Explore SigNoz API and verify attribute names
- Issue #2: Configure notification channel
- Issue #3: Create saved views (8 views)
- Issue #4: Create alert rules (4 alerts)
- Issue #5: Build Security Overview dashboard (6 panels)
- Issue #6: Test and validate all views/alerts/dashboards

---

## Execution Order

1. **Explore the SigNoz API first.** Check what endpoints exist for saved views, alerts, and dashboards.
2. **Verify attribute names.** Run test queries to confirm exact attribute names.
3. **Create saved views** (Task 1). Start with Security Events and Firewall Blocks.
4. **Ask Tony about notification channel preference** before creating alerts.
5. **Create alert rules** (Task 2). Start with Device Went Silent.
6. **Build the dashboard** (Task 3). Start with Firewall Blocks Over Time.
7. **Check baselines before setting alert thresholds.**

---

## What NOT To Do

- ❌ Do not create new containers or services
- ❌ Do not modify the OTel Collector config
- ❌ Do not modify rsyslog config
- ❌ Do not build a LangGraph agent or Telegram bot
- ❌ Do not add GeoIP enrichment
- ❌ Do not configure SNMP targets
- ❌ Do not create more than one dashboard
- ❌ Do not over-engineer alert rules

---

## Definition of Done

- [ ] At least 5 saved views created and accessible in SigNoz Logs Explorer
- [ ] Notification channel configured
- [ ] 4 alert rules created and active
- [ ] Security Overview dashboard with at least 4 panels showing live data
- [ ] All saved views tested — each returns relevant results
- [ ] Alert thresholds validated against actual data baselines
- [ ] Dashboard screenshot or link shared with Tony for review

---

## Reference

- **SigNoz API Reference:** https://signoz.io/api-reference/
- **SigNoz MCP Server:** https://github.com/SigNoz/signoz-mcp-server
- **SigNoz Dashboard Docs:** https://signoz.io/docs/dashboards/
- **SigNoz Alerts Docs:** https://signoz.io/docs/alerts/
- **Project Repo:** https://github.com/tbailey1712/first-light.git
- **SigNoz UI:** http://192.168.2.106:8081
