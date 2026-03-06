# CrowdSec pfSense Bouncer Setup

**Status:** API Key Generated ✅
**Next Step:** Install bouncer on pfSense

## Generated API Key

```
API Key: fHAuIVb2H5+MrfDcOzOnKoRbopple6TAomzPGND9szo
Bouncer Name: pfsense-firewall-bouncer
```

⚠️ **SAVE THIS KEY** - You cannot retrieve it again!

## Installation Steps

### Option 1: pfSense Package (Recommended)

1. **SSH to pfSense**
   ```bash
   ssh admin@firewall.mcducklabs.com
   ```

2. **Install CrowdSec Bouncer Package**
   ```bash
   pkg install crowdsec-firewall-bouncer
   ```

3. **Configure the Bouncer**

   Edit `/usr/local/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml`:

   ```yaml
   api_url: http://192.168.2.106:8080  # CrowdSec LAPI endpoint
   api_key: fHAuIVb2H5+MrfDcOzOnKoRbopple6TAomzPGND9szo

   # Firewall configuration
   mode: pf
   pf:
     anchor_name: crowdsec
     table_name: crowdsec_blacklist

   # Update frequency
   update_frequency: 10s

   # Logging
   log_mode: file
   log_dir: /var/log/crowdsec-firewall-bouncer/
   log_level: info

   # Ban duration
   ban_duration: 4h
   ```

4. **Enable and Start the Service**
   ```bash
   sysrc crowdsec_firewall_bouncer_enable="YES"
   service crowdsec-firewall-bouncer start
   ```

5. **Create pfSense Firewall Rule**

   **WebUI:** Firewall → Rules → WAN (or relevant interface)

   **Add rule at TOP of list:**
   - Action: Block
   - Interface: WAN
   - Source: Single host or alias → Create alias "crowdsec_blacklist" → Type: URL Table
   - Source Port: any
   - Destination: any
   - Destination Port: any
   - Description: "CrowdSec Auto-Ban"

   **Alias Configuration:**
   - Name: `crowdsec_blacklist`
   - Type: URL Table (IPs)
   - URL: `http://localhost:8080/v1/decisions/stream?startup=true`
   - Update Frequency: 1 hour

### Option 2: Manual Script

If package isn't available, use this script:

Create `/usr/local/bin/crowdsec-bouncer.sh`:

```bash
#!/bin/sh
# CrowdSec pfSense Bouncer

API_URL="http://192.168.2.106:8080"
API_KEY="fHAuIVb2H5+MrfDcOzOnKoRbopple6TAomzPGND9szo"
TABLE_NAME="crowdsec_blacklist"

# Fetch banned IPs from CrowdSec
BANNED_IPS=$(curl -s -H "X-Api-Key: ${API_KEY}" "${API_URL}/v1/decisions/stream?startup=true" | jq -r '.new[].value')

# Clear existing table
pfctl -t ${TABLE_NAME} -T flush

# Add banned IPs
for IP in $BANNED_IPS; do
    pfctl -t ${TABLE_NAME} -T add $IP
done

echo "[$(date)] Updated ${TABLE_NAME} with $(echo "$BANNED_IPS" | wc -l) IPs"
```

Make executable and add to cron:
```bash
chmod +x /usr/local/bin/crowdsec-bouncer.sh
echo "*/1 * * * * /usr/local/bin/crowdsec-bouncer.sh >> /var/log/crowdsec-bouncer.log 2>&1" | crontab -
```

## Verification

### 1. Check Bouncer Connection

On docker host:
```bash
docker exec fl-crowdsec cscli bouncers list
```

Should show:
```
Name                        IP Address      Valid  Last API pull
pfsense-firewall-bouncer    <pfSense IP>    ✓      <recent time>
```

### 2. Check Current Bans

```bash
docker exec fl-crowdsec cscli decisions list
```

### 3. Test Ban

On docker host, trigger a ban:
```bash
docker exec fl-crowdsec cscli decisions add --ip 1.2.3.4 --duration 1h --reason "Test ban"
```

On pfSense, check table:
```bash
pfctl -t crowdsec_blacklist -T show
```

Should show `1.2.3.4`

### 4. Verify Blocking

Try to connect from banned IP - should be blocked at firewall level.

## Monitoring

### View Bouncer Logs

```bash
tail -f /var/log/crowdsec-firewall-bouncer/crowdsec-firewall-bouncer.log
```

### View CrowdSec Decisions

```bash
docker exec fl-crowdsec cscli decisions list
docker exec fl-crowdsec cscli metrics
```

### View pfSense Block Log

```bash
tcpdump -n -e -ttt -i pflog0
```

## Troubleshooting

**Bouncer not connecting:**
- Check API key is correct
- Verify CrowdSec LAPI is accessible from pfSense: `curl -H "X-Api-Key: YOUR_KEY" http://192.168.2.106:8080/v1/decisions`
- Check firewall rules allow pfSense → docker host:8080

**IPs not being blocked:**
- Verify pfSense firewall rule is at TOP of list
- Check table exists: `pfctl -t crowdsec_blacklist -T show`
- Verify rule is enabled and not disabled

**Too many blocks:**
- Adjust CrowdSec scenarios if too aggressive
- Whitelist trusted IPs: `docker exec fl-crowdsec cscli decisions delete --ip YOUR_IP`

## Expected Behavior

Once configured:
1. CrowdSec detects attacks (SSH brute force, web scanning, etc.)
2. Creates ban decisions (default 4h)
3. pfSense bouncer fetches decisions every 10 seconds
4. Adds IPs to `crowdsec_blacklist` table
5. pfSense firewall rule blocks all traffic from those IPs
6. After ban expires, IP is removed

**Result:** Automatic threat response in ~10 seconds instead of hours/days!

## Security Impact

**Before:** Detection only - attackers can keep trying
**After:** Auto-ban - attackers are blocked after first detection

**Average time to block:** 10-30 seconds
**Ban duration:** 4 hours (configurable)
**Community intelligence:** Shares bans with global CrowdSec network
