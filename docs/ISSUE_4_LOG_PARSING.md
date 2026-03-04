# Issue #4: Parse UniFi, AdGuard, and Proxmox Logs

## Objective
Extract structured data from currently unparsed logs to enable AI analysis and visualization.

## Current State (from CrowdSec metrics)
```
UniFi APs: 410,000 lines unparsed
AdGuard:    35,000 lines unparsed
Proxmox:    26,000 lines unparsed
QNAP NAS:      151 lines unparsed
```

These logs flow into SigNoz but lack structured attributes, making them useless for:
- AI analysis (can't query specific fields)
- Dashboards (can't group/filter)
- Alerts (can't trigger on conditions)
- CrowdSec security detection

## Why This Matters

**Without parsing:**
```
body: "Feb 25 14:23:42 UniFiSecondFloorBack hostapd: wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: authenticated"
```

**With parsing:**
```
body: "Feb 25 14:23:42 UniFiSecondFloorBack hostapd: wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: authenticated"
attributes:
  unifi.interface: "wlan0"
  unifi.event: "authenticated"
  unifi.client_mac: "aa:bb:cc:dd:ee:ff"
  unifi.service: "hostapd"
  network.zone: "wireless"
```

Now the AI can query: "Show me all wireless auth failures in the last hour" or "Which clients are roaming frequently?"

## Parsing Strategy

### Two-Layer Approach

**Layer 1: OTel Collector (for SigNoz/AI)**
- Extract attributes for querying/visualization
- Add in `signoz/otel-collector-config.yaml`
- Uses OTTL (OpenTelemetry Transformation Language)

**Layer 2: CrowdSec (for security detection - optional)**
- Extract security-relevant events
- Create custom parsers in `/crowdsec/parsers/`
- Only needed if we want CrowdSec to detect threats in these logs

**Recommendation:** Start with Layer 1 (OTel) only. Add CrowdSec parsers later if needed.

## Implementation Plan

### 1. UniFi Access Point Logs

**Sample logs to parse:**
```
hostapd: wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: authenticated
hostapd: wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated
hostapd: wlan0: STA aa:bb:cc:dd:ee:ff WPA: pairwise key handshake completed (RSN)
kernel: [12345.678] wlan0: deauthenticating from aa:bb:cc:dd:ee:ff by local choice (Reason: 3=DEAUTH_LEAVING)
```

**Attributes to extract:**
- `unifi.service` - hostapd, kernel, etc.
- `unifi.interface` - wlan0, wlan1, eth0
- `unifi.event` - authenticated, associated, deauthenticated, etc.
- `unifi.client_mac` - MAC address of wireless client
- `unifi.reason` - Deauth/disassoc reason code
- `network.zone` = "wireless"

**OTel processor (add to `signoz/otel-collector-config.yaml`):**
```yaml
processors:
  transform/unifi:
    log_statements:
      - context: log
        conditions:
          - IsMatch(resource.attributes["host.name"], "^UniFi.*")
        statements:
          # Set network zone
          - set(attributes["network.zone"], "wireless")
          - set(attributes["device.type"], "access-point")

          # Extract interface (wlan0, wlan1, eth0)
          - set(attributes["unifi.interface"], ExtractPatterns(body, "(?P<iface>wlan\\d+|eth\\d+):"))

          # Extract client MAC
          - set(attributes["unifi.client_mac"], ExtractPatterns(body, "STA (?P<mac>[0-9a-f:]{17})"))

          # Extract event type
          - set(attributes["unifi.event"], "authenticated") where IsMatch(body, "authenticated")
          - set(attributes["unifi.event"], "associated") where IsMatch(body, "associated")
          - set(attributes["unifi.event"], "deauthenticated") where IsMatch(body, "deauthenticating")
          - set(attributes["unifi.event"], "disassociated") where IsMatch(body, "disassociated")
          - set(attributes["unifi.event"], "handshake_completed") where IsMatch(body, "key handshake completed")
```

### 2. AdGuard Home Logs

**Sample logs to parse:**
```
2026/02/25 14:23:42 [info] 192.168.1.100 example.com A
2026/02/25 14:23:42 [info] 192.168.1.100 ads.tracker.com AAAA blocked by filter
2026/02/25 14:23:42 [info] 192.168.1.100 safe.example.com A cached
```

**Attributes to extract:**
- `adguard.client_ip` - Source IP making DNS query
- `adguard.domain` - Domain being queried
- `adguard.query_type` - A, AAAA, CNAME, etc.
- `adguard.action` - allowed, blocked, cached
- `adguard.blocked_by` - Which filter blocked it (if blocked)
- `network.zone` - Based on IP range

**OTel processor:**
```yaml
processors:
  transform/adguard:
    log_statements:
      - context: log
        conditions:
          - resource.attributes["host.name"] == "adguard"
        statements:
          - set(attributes["device.type"], "dns-filter")

          # Parse log format: IP domain query_type [action]
          - set(attributes["adguard.client_ip"], ExtractPatterns(body, "\\] (?P<ip>[0-9.]+) "))
          - set(attributes["adguard.domain"], ExtractPatterns(body, "[0-9.]+ (?P<domain>\\S+) "))
          - set(attributes["adguard.query_type"], ExtractPatterns(body, "\\S+ (?P<type>A|AAAA|CNAME|MX|TXT|PTR)"))

          # Determine action
          - set(attributes["adguard.action"], "blocked") where IsMatch(body, "blocked")
          - set(attributes["adguard.action"], "cached") where IsMatch(body, "cached")
          - set(attributes["adguard.action"], "allowed") where attributes["adguard.action"] == nil
```

### 3. Proxmox VE Logs

**Sample logs to parse:**
```
pvedaemon[1234]: <root@pam> starting task UPID:pve:00001234:12345678:5ABC1234:qmstart:100:root@pam:
pvedaemon[1234]: <root@pam> end task UPID:pve:00001234:12345678:5ABC1234:qmstart:100:root@pam: OK
kernel: [12345.678] zfs: pool rpool degraded
```

**Attributes to extract:**
- `proxmox.user` - User performing action
- `proxmox.task` - qmstart, qmstop, backup, etc.
- `proxmox.vmid` - VM ID (100, 101, etc.)
- `proxmox.status` - OK, FAILED
- `proxmox.upid` - Unique task ID
- `device.type` = "hypervisor"

**OTel processor:**
```yaml
processors:
  transform/proxmox:
    log_statements:
      - context: log
        conditions:
          - resource.attributes["host.name"] == "pve" or resource.attributes["host.name"] == "pve.mcducklabs.com"
        statements:
          - set(attributes["device.type"], "hypervisor")

          # Extract user
          - set(attributes["proxmox.user"], ExtractPatterns(body, "<(?P<user>[^>]+)>"))

          # Extract task type
          - set(attributes["proxmox.task"], ExtractPatterns(body, "UPID:pve:[^:]+:[^:]+:[^:]+:(?P<task>[^:]+):"))

          # Extract VM ID
          - set(attributes["proxmox.vmid"], ExtractPatterns(body, ":(?P<vmid>\\d+):root@pam"))

          # Extract status
          - set(attributes["proxmox.status"], "OK") where IsMatch(body, ": OK$")
          - set(attributes["proxmox.status"], "FAILED") where IsMatch(body, ": FAILED")
```

### 4. SSH/Sudo Logs (SECURITY - HIGH PRIORITY)

**Current state:** CrowdSec shows 298 SSH log lines, but only 4 parsed (294 unparsed!)

**Sample logs to parse:**
```
sshd[12345]: Failed password for invalid user admin from 123.45.67.89 port 54321 ssh2
sshd[12345]: Accepted publickey for root from 192.168.1.100 port 12345 ssh2: RSA SHA256:abc123...
sshd[12345]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=123.45.67.89 user=root
sudo: tbailey : TTY=pts/0 ; PWD=/home/tbailey ; USER=root ; COMMAND=/usr/bin/docker ps
sudo: pam_unix(sudo:auth): authentication failure; logname=tbailey uid=1000 euid=0 tty=/dev/pts/0 ruser=tbailey rhost=  user=tbailey
```

**Attributes to extract:**
- `ssh.event` - failed_password, accepted_publickey, session_opened, session_closed
- `ssh.user` - Username attempting auth
- `ssh.source_ip` - Source IP of SSH connection
- `ssh.source_port` - Source port
- `ssh.method` - publickey, password
- `sudo.user` - User running sudo
- `sudo.command` - Command being run
- `sudo.status` - success, failure
- `security.event_type` - auth_failure, auth_success, privilege_escalation

**OTel processor:**
```yaml
processors:
  transform/ssh_sudo:
    log_statements:
      - context: log
        conditions:
          - IsMatch(body, "sshd\\[") or IsMatch(body, "sudo:")
        statements:
          - set(attributes["security.event_type"], "authentication")

          # SSH failed password
          - set(attributes["ssh.event"], "failed_password") where IsMatch(body, "Failed password")
          - set(attributes["ssh.user"], ExtractPatterns(body, "for (?:invalid user )?(?P<user>\\S+) from"))
          - set(attributes["ssh.source_ip"], ExtractPatterns(body, "from (?P<ip>[0-9.]+) port"))
          - set(attributes["security.event_type"], "auth_failure") where IsMatch(body, "Failed password")

          # SSH accepted key
          - set(attributes["ssh.event"], "accepted_publickey") where IsMatch(body, "Accepted publickey")
          - set(attributes["ssh.user"], ExtractPatterns(body, "for (?P<user>\\S+) from"))
          - set(attributes["ssh.source_ip"], ExtractPatterns(body, "from (?P<ip>[0-9.]+) port"))
          - set(attributes["ssh.method"], "publickey") where IsMatch(body, "Accepted publickey")
          - set(attributes["security.event_type"], "auth_success") where IsMatch(body, "Accepted")

          # Sudo commands
          - set(attributes["sudo.user"], ExtractPatterns(body, "sudo:\\s+(?P<user>\\S+)\\s+:")) where IsMatch(body, "sudo:")
          - set(attributes["sudo.command"], ExtractPatterns(body, "COMMAND=(?P<cmd>.+)$"))
          - set(attributes["security.event_type"], "privilege_escalation") where IsMatch(body, "sudo:") and IsMatch(body, "COMMAND=")

          # Sudo auth failures
          - set(attributes["sudo.status"], "failure") where IsMatch(body, "sudo:.*authentication failure")
          - set(attributes["security.event_type"], "auth_failure") where IsMatch(body, "sudo:.*authentication failure")
```

**CrowdSec parsers:** Already installed but not working!
- `crowdsecurity/sshd-logs` - Already exists, should parse but isn't

**Why SSH logs aren't parsing:**
Need to check CrowdSec acquis.yml - may need to add SSH log source or fix grok patterns.

### 5. QNAP NAS Logs (Low Priority)

Only 151 lines - defer until we see what the actual log format is.

## Testing Strategy

For each parser:

1. **Get sample logs:**
   ```bash
   sudo docker exec fl-rsyslog tail -100 /var/log/remote/UniFiSecondFloorBack/syslog.log
   ```

2. **Test regex patterns** before adding to OTel config

3. **Deploy parser** to `signoz/otel-collector-config.yaml`

4. **Restart OTel collector:**
   ```bash
   cd /opt/first-light
   sudo docker compose restart signoz-otel-collector
   ```

5. **Verify in SigNoz:**
   - Open Logs Explorer
   - Find a log from that device
   - Check Attributes tab - should see new fields

6. **Test queries:**
   - Filter by new attribute
   - Group by new attribute
   - Create visualization

## Success Criteria

- [ ] UniFi logs show `unifi.event`, `unifi.client_mac`, `unifi.interface`
- [ ] AdGuard logs show `adguard.domain`, `adguard.action`, `adguard.client_ip`
- [ ] Proxmox logs show `proxmox.task`, `proxmox.vmid`, `proxmox.user`
- [ ] Can query: "Show me all blocked DNS queries in last hour"
- [ ] Can query: "Show me all wireless auth failures"
- [ ] Can query: "Show me all Proxmox VM starts/stops"
- [ ] AI agent can analyze structured data instead of raw text

## AI Agent Benefits

Once parsed, the AI can answer:
- "Which wireless clients are having auth issues?"
- "What domains is 192.168.1.100 trying to access that are blocked?"
- "Show me all VM operations in the last 24 hours"
- "Are there any patterns in the blocked AdGuard domains?"
- "Which UniFi AP has the most client roaming?"

Without parsing, it can only search raw text.

## CrowdSec Parsers (Phase 2 - Optional)

If we want CrowdSec to detect threats in these logs:

1. **UniFi:** Detect deauth attacks, rogue APs, excessive failures
2. **AdGuard:** Detect DNS tunneling, DGA domains, DNS exfiltration
3. **Proxmox:** Detect unauthorized VM access, suspicious operations

Create custom parsers in `/crowdsec/parsers/s01-parse/`:
- `unifi-logs.yaml`
- `adguard-logs.yaml`
- `proxmox-logs.yaml`

And scenarios in `/crowdsec/scenarios/`:
- `unifi-deauth-attack.yaml`
- `adguard-dns-tunneling.yaml`

**Defer this** until Phase 3 (AI Agent is higher priority).

## Implementation Order

1. **SSH/Sudo** (SECURITY - 298 logs, 294 unparsed, critical for detecting break-ins)
2. **UniFi** (highest volume - 410k logs, wireless security)
3. **AdGuard** (DNS visibility, 35k logs, detect exfiltration/malware)
4. **Proxmox** (VM operations, 26k logs)
5. **QNAP** (only 151 logs, low priority)

Estimate: 1-2 hours per parser (including testing).

**Security Impact:**
- SSH parser = Detect brute force, unauthorized access
- UniFi parser = Detect deauth attacks, rogue devices
- AdGuard parser = Detect DNS tunneling, C2 callbacks

## Next Steps After Parsing

Once logs are structured:
- Create saved views for common queries
- Build dashboards (wireless clients, DNS blocks, VM activity)
- Create alerts (excessive auth failures, VM state changes)
- **Feed structured data to AI agent** (Issue #5)
