# Maximizing ntopng Community Data for First Light

ntopng 6.7 Community on aarch64 — configuration guide to get the most data
out of the free edition for First Light.

---

## 1. Enable Prometheus Metrics Export

ntopng Community Edition does **not** have a Prometheus toggle in the UI.
You must enable it via a command-line flag in the ntopng config file.

**Steps:**
1. SSH into the ntopng host (192.168.1.5)
2. Edit the ntopng config: `sudo nano /etc/ntopng/ntopng.conf`
3. Add this line:
   ```
   --prometheus-exporter-port=9000
   ```
4. Restart ntopng: `sudo systemctl restart ntopng`
5. Verify: `curl http://192.168.1.5:9000/metrics | head -20`

> **Note:** The Prometheus metrics endpoint will be on port 9000 (separate
> from the web UI on port 3000), at `http://192.168.1.5:9000/metrics`

Update `.env` to set `NTOPNG_PROMETHEUS_PORT=9000` once enabled.

**What you get:**
- Per-interface traffic (bytes/sec in/out)
- Per-host traffic (top talkers)
- Protocol breakdown (HTTP, DNS, TLS, etc.)
- Active flows count
- Alert counts

---

## 2. Configure All Network Interfaces

Make sure ntopng is monitoring all relevant interfaces (especially the one
that sees inter-VLAN traffic).

**Steps:**
1. Go to **Settings → Preferences → Interfaces**
2. Verify all relevant interfaces are listed and active
3. For a managed switch, the interface that sees all VLANs (typically the
   trunk port or the firewall uplink) is most valuable
4. Restart ntopng if you add interfaces: `systemctl restart ntopng`

---

## 3. Enable Flow Collection from pfSense

pfSense can export NetFlow/IPFIX data to ntopng, dramatically improving
visibility — this gives ntopng per-flow records including source/destination
IPs, ports, and bytes.

**On pfSense:**
1. Install the **softflowd** package:
   `System → Package Manager → Available Packages → softflowd`
2. Configure softflowd:
   `Services → softflowd`
   - Interface: WAN (or the interface you want to monitor)
   - Host: `192.168.1.5`
   - Port: `2055` (NetFlow v9)
   - Version: NetFlow v9

**On ntopng:**
1. Go to **Settings → Preferences → Interfaces**
2. Add a new interface: `udp://0.0.0.0:2055` (NetFlow listener)
3. Restart ntopng

> **Note:** Community edition can receive and display flows from softflowd.
> Historical flow export and nProbe integration require Enterprise.

---

## 4. Enable Host Alerts

Configure ntopng to generate alerts that First Light can pick up via the API.

**Steps:**
1. Go to **Settings → Alerts → Alert Endpoints**
2. Enable **"Syslog"** alert endpoint
3. Configure syslog to send to First Light's Alloy syslog listener:
   - Host: `docker.mcducklabs.com`
   - Port: `5515` (separate port from pfSense)
4. Go to **Settings → Alerts → Behavioral Checks**
5. Enable relevant checks:
   - **SYN flood** detection
   - **DNS flood** detection
   - **Blacklisted hosts** contacted
   - **Flow flood** detection
   - **Unexpected traffic** (hosts talking to new countries)
   - **Score-based alerts** (threshold: recommended 100)

---

## 5. Enable Blacklist Checking

ntopng Community includes threat intelligence blacklists at no cost.

**Steps:**
1. Go to **Settings → Preferences → Categorization**
2. Enable **"ntopng Threat Intelligence"** (free, community-sourced)
3. Enable **"Geo IP"** for country-level flow tracking
4. These fire alerts when a host contacts a known-malicious IP

---

## 6. Configure Data Retention

Community edition stores data in Redis in-memory. Maximize what it keeps:

**Steps:**
1. Go to **Settings → Preferences → Data Retention**
2. Set timeseries retention to maximum allowed (usually 30 days in Community)
3. If the host has >4GB RAM, you can increase Redis memory in `/etc/ntopng.conf`:
   ```
   --redis-max-memory=2gb
   ```

---

## 7. REST API Setup for First Light

First Light uses the ntopng REST API to query top talkers, active alerts,
and interface statistics.

**Create a dedicated API user:**
1. Go to **Settings → Users**
2. Add user: `firstlight`
3. Role: **"Administrator"** (needed for full API access in Community)
4. Set a strong password and add to `.env` as `NTOPNG_PASSWORD`

**Useful Community API endpoints First Light will use:**
```
GET /lua/rest/v2/get/interface/data.lua?ifid=0    # Interface stats
GET /lua/rest/v2/get/host/top_talkers.lua         # Top bandwidth users
GET /lua/rest/v2/get/ntopng/interfaces.lua         # List interfaces
GET /lua/rest/v2/get/alert/list_engaged.lua        # Active alerts
GET /lua/metrics.lua                               # Prometheus metrics
```

---

## 8. What You Won't Get (Community Limitations)

Be aware these require ntopng Enterprise:
- **Historical flow records** (who talked to whom, when, for how long)
- **nProbe integration** (deep DPI and enriched flows)
- **SNMP device polling** within ntopng
- **Flow export** to external systems
- **User behavior analytics**

**First Light workaround:** The Alloy stack will capture pfSense firewall
logs (which includes src/dst IP and port for allowed/blocked flows) and
combine with ntopng's real-time views to give a similar picture.

---

## Quick Verification Checklist

After completing setup, verify with:

```bash
# Prometheus metrics working
curl -s http://192.168.1.5:3000/lua/metrics.lua | head -20

# API responding
curl -s -u firstlight:PASSWORD \
  "http://192.168.1.5:3000/lua/rest/v2/get/ntopng/interfaces.lua"

# Alerts endpoint
curl -s -u firstlight:PASSWORD \
  "http://192.168.1.5:3000/lua/rest/v2/get/alert/list_engaged.lua"
```
