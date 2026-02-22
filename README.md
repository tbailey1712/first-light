# First Light — Network Observability & Threat Intelligence

Phase 1 MVP: CrowdSec threat detection + SigNoz unified observability platform

## Architecture

```
Network Sources (pfSense, QNAP, Proxmox, etc.)
           │
           │ syslog UDP/TCP 514
           ▼
      ┌─────────┐
      │ rsyslog │ (fan-out router)
      └────┬────┘
           │
     ┌─────┴──────┐
     │            │
     ▼            ▼
┌────────┐   ┌──────────────┐
│ SigNoz │   │ /var/log/    │
│ (OTel) │   │   remote/    │
│        │   │   {host}/    │
│ ClickHouse   └──────┬───────┘
│ Logs UI │          │ tail
└────────┘           ▼
              ┌────────────┐
              │  CrowdSec  │
              │  (threat   │
              │ detection) │
              └────────────┘
```

## Quick Start — Local Dev

```bash
git clone <repo>
cd first-light
cp .env.example .env
# Edit .env if you have a CrowdSec enrollment key (optional)

docker compose up -d

# Wait for all services to start (2-3 minutes)
docker compose ps

# Send test syslog messages
./scripts/test-syslog.sh

# Open SigNoz UI
open http://localhost:3301

# Check CrowdSec alerts
docker exec fl-crowdsec cscli alerts list
```

## Production Deployment — Portainer Stack

1. In Portainer: **Stacks → Add Stack → Git Repository**
2. Repository URL: `<your-git-repo-url>`
3. Reference: `refs/heads/main`
4. Compose path: `docker-compose.yml`
5. Environment variables:
   - `CROWDSEC_ENROLLMENT_KEY` (optional, from app.crowdsec.net)
6. Enable **Git auto-update** or use webhook

**Important:** Portainer ignores `docker-compose.override.yml` (which is for local dev only). It uses only `docker-compose.yml`.

## Configure Network Devices

Point your network devices' syslog to the Docker host on port 514:

### pfSense
`Status → System Logs → Settings → Remote Logging`
- Remote log servers: `<docker-host-ip>:514` (UDP)
- Send everything

### QNAP NAS
`Control Panel → System → System Logs → Syslog`
- Remote syslog server: `<docker-host-ip>:514` (UDP)

### Proxmox VE
Edit `/etc/rsyslog.conf` on each PVE host:
```bash
*.* @<docker-host-ip>:514
```
Restart: `systemctl restart rsyslog`

### UniFi Controller
`Settings → System → Remote Logging`
- IP Address: `<docker-host-ip>`
- Port: 514

## Directory Structure

```
first-light/
├── docker-compose.yml              # Production compose (with include)
├── docker-compose.override.yml     # Local dev overrides (auto-merged)
├── .env.example                    # Template
├── .env                            # Your values (gitignored)
│
├── rsyslog/
│   └── rsyslog.conf                # Fan-out routing config
│
├── crowdsec/
│   └── acquis.yml                  # Log file → parser mapping
│
├── signoz/
│   ├── docker-compose.yaml         # SigNoz's official compose
│   ├── otel-collector-config.yaml  # Custom config (added syslog receiver)
│   └── common/                     # SigNoz configs
│
└── scripts/
    └── test-syslog.sh              # Send test messages
```

## Verify Data Flow

### Check rsyslog is receiving
```bash
docker logs fl-rsyslog --tail 50
```

### Check SigNoz has logs
1. Open http://localhost:3301 (or 8080 in production)
2. Navigate to **Logs Explorer**
3. Should see incoming syslog messages

### Check CrowdSec is parsing
```bash
# List alerts (simulated brute force from test script should appear)
docker exec fl-crowdsec cscli alerts list

# Check parsers are loaded
docker exec fl-crowdsec cscli parsers list

# Check scenarios
docker exec fl-crowdsec cscli scenarios list
```

### Check log files are being written
```bash
docker exec fl-rsyslog ls -lah /var/log/remote/
# Should see directories for each host sending syslog
```

## Ports

**Local Development (Mac):**
- rsyslog: 1514 UDP/TCP (mapped to 514 in container)
- SigNoz UI: 3301 (mapped to 3000)
- SigNoz OTel: 4317 (gRPC), 4318 (HTTP)

**Production:**
- rsyslog: 514 UDP/TCP (standard syslog)
- SigNoz UI: 8080
- SigNoz OTel: 4317, 4318

## Next Steps — Phase 2

Once logs are flowing and CrowdSec is detecting threats:

1. Add CrowdSec bouncer for pfSense (automated blocking)
2. Build LLM analysis harness (REST API)
3. Add scheduler for automated daily/weekly digests
4. Build custom console UI

---

**Phase 1 Status:** ✅ MVP Complete (data pipeline + detection)
**Phase 2 Status:** 🔜 Planning (LLM harness)
