# First Light — Data Retention Policy

## Overview

All First Light volumes run on `docker.mcducklabs.com` (192.168.2.106).
This policy defines retention periods, implementation method, and rationale
for each data store.

**Last audited:** 2026-05-05
**Total disk before grooming:** ~55 GB across all FL-related volumes

---

## Retention Schedule

| Volume | Current Size | Retention | Method | Rationale |
|---|---|---|---|---|
| `fl-syslog-files` | 18.34 GB | **7 days** | logrotate in rsyslog container | CrowdSec processes logs within hours; 7d covers weekly report lookback. Biggest single win (~16 GB reclaimed). |
| `signoz-clickhouse` (system tables) | 7.5 GB | **3 days** | ALTER TABLE ... MODIFY TTL | `query_log`, `trace_log`, `processors_profile_log`, `metric_log`, `part_log`, `asynchronous_metric_log` are ClickHouse internal debug/profiling. Not used by any FL tooling. |
| `signoz-clickhouse` (logs_v2) | 862 MB | **30 days** | ALTER TABLE ... MODIFY TTL | Daily report looks back 24h. Weekly report looks back 7d. 30d covers any ad-hoc investigation with margin. |
| `signoz-clickhouse` (samples_v4) | 509 MB | **90 days** | ALTER TABLE ... MODIFY TTL | Metrics are compact. 90d supports baseline trending and eval comparisons. |
| `signoz-clickhouse` (time_series_v4) | 48 MB | **90 days** | ALTER TABLE ... MODIFY TTL | Metadata table for samples; must match samples retention. |
| `langfuse_clickhouse_data` | 22.77 GB | **Not managed** | Langfuse's own lifecycle — do not touch | Third-party app manages its own retention |
| `fl-agent-reports` | 600 KB | **90 days** | APScheduler job in scheduler.py | Weekly report reads past dailies. Tiny volume, low priority. |
| `fl-redis-data` | 3 KB | **No action** | Self-managing (baseline overwrite, TTL on conversation keys) | — |
| `fl-crowdsec-data` | 75 MB | **No action** | CrowdSec manages its own decision expiry | — |
| `fl-threat-intel-cache` | 1.4 MB | **No action** | Internal TTL (24h per entry) | — |

---

## Implementation Plan

### Phase 1: Syslog rotation (saves ~16 GB)

**What:** Add logrotate to the rsyslog container to rotate per-host log files daily, keeping 7 days.

**Files to modify:**
- `rsyslog/logrotate.conf` — new file, logrotate config for `/var/log/remote/*/syslog.log`
- `rsyslog/Dockerfile` — install logrotate, add cron entry
- `docker-compose.yaml` — no changes needed (volume already mounted)

**logrotate.conf:**
```
/var/log/remote/*/syslog.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

**Dockerfile additions:**
```dockerfile
RUN apt-get update && apt-get install -y logrotate cron && rm -rf /var/lib/apt/lists/*
COPY logrotate.conf /etc/logrotate.d/syslog-remote
RUN echo "0 2 * * * /usr/sbin/logrotate /etc/logrotate.d/syslog-remote" >> /etc/crontab
```

**Risk:** `copytruncate` avoids needing to signal rsyslog (no missed logs during rotation). CrowdSec reads from the active file — rotated-away data is already processed.

---

### Phase 2: ClickHouse system table TTL (saves ~7 GB)

**What:** Set 3-day TTL on ClickHouse internal profiling tables.

**Method:** Run ALTER TABLE commands against `signoz-clickhouse` container:

```sql
ALTER TABLE system.query_log MODIFY TTL event_date + INTERVAL 3 DAY;
ALTER TABLE system.trace_log MODIFY TTL event_date + INTERVAL 3 DAY;
ALTER TABLE system.processors_profile_log MODIFY TTL event_date + INTERVAL 3 DAY;
ALTER TABLE system.metric_log MODIFY TTL event_date + INTERVAL 3 DAY;
ALTER TABLE system.part_log MODIFY TTL event_date + INTERVAL 3 DAY;
ALTER TABLE system.asynchronous_metric_log MODIFY TTL event_date + INTERVAL 3 DAY;
ALTER TABLE system.query_views_log MODIFY TTL event_date + INTERVAL 3 DAY;
```

**Risk:** Low. These tables are ClickHouse self-diagnostics. No FL tooling reads them. ClickHouse respects TTL on merge — space reclaimed gradually (force with `OPTIMIZE TABLE ... FINAL` if needed).

**Persistence:** TTL is stored in table metadata — survives container restarts. One-time operation.

---

### Phase 3: SigNoz data table TTL (caps growth)

**What:** Set retention on the actual observability data tables.

```sql
-- Logs: 30 days
ALTER TABLE signoz_logs.logs_v2 MODIFY TTL timestamp + INTERVAL 30 DAY;

-- Metrics: 90 days
ALTER TABLE signoz_metrics.samples_v4 MODIFY TTL toDateTime(intDiv(unix_milli, 1000)) + INTERVAL 90 DAY;
ALTER TABLE signoz_metrics.time_series_v4 MODIFY TTL toDateTime(intDiv(unix_milli, 1000)) + INTERVAL 90 DAY;
ALTER TABLE signoz_metrics.samples_v4_agg_5m MODIFY TTL toDateTime(intDiv(unix_milli, 1000)) + INTERVAL 90 DAY;
ALTER TABLE signoz_metrics.samples_v4_agg_30m MODIFY TTL toDateTime(intDiv(unix_milli, 1000)) + INTERVAL 90 DAY;
```

**Risk:** Medium. Need to verify the TTL column types match — `timestamp` for logs (DateTime64), `unix_milli` for metrics (UInt64, needs `toDateTime()` wrapper). Incorrect TTL expression will be rejected by ClickHouse (safe failure). Data loss is intentional and bounded.

**Validation:** Before applying, confirm column types:
```sql
SELECT name, type FROM system.columns WHERE database = 'signoz_logs' AND table = 'logs_v2' AND name = 'timestamp';
SELECT name, type FROM system.columns WHERE database = 'signoz_metrics' AND table = 'samples_v4' AND name = 'unix_milli';
```

---

### Phase 4: Report file cleanup (minor)

**What:** Cron job to delete daily report files older than 90 days.

**Method:** Add to fl-agent container's scheduler or as a host-level cron:
```bash
find /opt/first-light/reports -name "*.md" -mtime +90 -delete
find /opt/first-light/reports -name "*.json" -mtime +90 -delete
```

**Risk:** None. Reports are already in Slack history and Langfuse traces.

---

## Build Sequence

1. Phase 1 (syslog) — biggest impact, lowest risk, self-contained
2. Phase 2 (system tables) — one-time SQL, immediate space recovery
3. Phase 3 (data tables) — validate column types first, then apply
4. Phase 4 (reports) — trivial, do anytime

**Out of scope:** Langfuse ClickHouse — managed by Langfuse's own lifecycle. If it grows too large, configure via Langfuse's application settings, not raw ALTER TABLE.

## Rollback

- **Syslog:** Remove logrotate config, rebuild container. Old logs already gone (by design).
- **ClickHouse TTL:** `ALTER TABLE ... REMOVE TTL` reverses the policy. Already-deleted data is gone.

There is no way to recover data after TTL deletes it. This is acceptable because:
- Syslog files are ephemeral (CrowdSec processes in real-time)
- ClickHouse system tables are regenerated continuously
- Observability data older than retention period has already been synthesized into daily/weekly reports
- Forensic coverage for slow-burn scenarios (>30 days) relies on Langfuse trace history and Slack report archives rather than raw logs

---

## Monitoring

After implementation, add to the infrastructure agent's health check:
- `fl-syslog-files` volume should stabilize at ~3-4 GB (7 days × ~500 MB/day)
- `signoz-clickhouse` should drop to ~5 GB within a week (system tables purge)
- Track via existing `docker system df` or add a Prometheus metric
