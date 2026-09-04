#!/usr/bin/env bash
# Configure rsyslog to forward logs to the First Light OTel collector.
# Run with sudo on any Ubuntu/Debian host, VM or LXC container.
#
#   sudo ./setup_remote_syslog.sh
#
# The collector's syslog receiver is TCP 5140, protocol rfc3164
# (see signoz/otel-collector-config.yaml -> receivers.syslog).

set -euo pipefail

SYSLOG_HOST="${SYSLOG_HOST:-192.168.2.106}"
SYSLOG_PORT="${SYSLOG_PORT:-5140}"

[[ $EUID -ne 0 ]] && { echo "Run as root or with sudo."; exit 1; }

# --- Preflight: DMZ (VLAN 4) hosts are outbound-restricted. Fail loudly here
# rather than silently forwarding into a blackhole.
echo -n "Checking ${SYSLOG_HOST}:${SYSLOG_PORT} ... "
if timeout 5 bash -c "cat </dev/null >/dev/tcp/${SYSLOG_HOST}/${SYSLOG_PORT}" 2>/dev/null; then
    echo "reachable"
else
    echo "UNREACHABLE"
    echo "Add a firewall rule permitting this host -> ${SYSLOG_HOST}:${SYSLOG_PORT}/tcp, then re-run."
    exit 1
fi

if ! command -v rsyslogd &>/dev/null; then
    apt-get update -qq && apt-get install -y rsyslog
fi

# --- Detect a pre-existing forwarder. Several hosts were configured by hand with
# the legacy selector syntax (e.g. adguard: `*.* @192.168.2.106:514`). Adding a
# second action would forward every message TWICE.
EXISTING=$(grep -rlsE '^[^#]*(@@?[0-9]|omfwd)' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null \
           | grep -v '90-first-light.conf' || true)
if [[ -n "$EXISTING" ]]; then
    echo
    echo "!! An existing syslog forwarder was found in:"
    for f in $EXISTING; do printf '   %s: ' "$f"; grep -hsE '^[^#]*(@@?[0-9]|omfwd)' "$f" | head -2; done
    if [[ "${REPLACE_EXISTING:-0}" == "1" ]]; then
        for f in $EXISTING; do mv -v "$f" "$f.disabled-by-first-light"; done
        echo "   Disabled (renamed to *.disabled-by-first-light)."
    else
        echo
        echo "   Refusing to add a second forwarder - you would get duplicate logs."
        echo "   Re-run with REPLACE_EXISTING=1 to disable the old config, or remove it by hand."
        exit 1
    fi
fi

# Patch base rsyslog.conf. Applies to bare metal (e.g. the pve hypervisor) as
# well as containers:
#   imklog   - unnecessary once imjournal is on, since journald already collects
#              kmsg; leaving both enabled double-collects kernel messages. It
#              also cannot work in a container, which has no /proc/kmsg.
#   imuxsock - journald owns /dev/log. Reading both it and the journal delivers
#              every message twice, so the socket input is turned off.
sed -i \
    -e 's|^module(load="imklog"|#module(load="imklog"|' \
    -e 's|^module(load="imuxsock")|module(load="imuxsock" SysSock.Use="off")|' \
    /etc/rsyslog.conf

# Read the journal, so units that log only to journald (sshd on modern Ubuntu)
# are still forwarded.
mkdir -p /var/spool/rsyslog
# IgnorePreviousMessages is essential. Without it, imjournal's first run
# replays the ENTIRE journal history. On the pve hypervisor (2026-09-04) that
# meant 1,776,519 messages lost to rate-limiting, rsyslog pinned at a full core
# and 1.8 GB RSS, and a flood of backfilled records. RFC3164 carries no year, so
# replayed entries from previous years are stamped with the CURRENT year - any
# dated after today land in the future and corrupt freshness checks.
#
# The state file must not already exist for this to take effect, so it is
# removed here: we deliberately want "start from now", not "resume the backlog".
rm -f /var/spool/rsyslog/imjournal.state
cat > /etc/rsyslog.d/10-imjournal.conf <<'EOF'
global(workDirectory="/var/spool/rsyslog")
module(load="imjournal"
       StateFile="imjournal.state"
       IgnorePreviousMessages="on"
       FileCreateMode="0644"
       Ratelimit.Interval="60"
       Ratelimit.Burst="20000")
EOF

# Forward everything to First Light.
#
#   template  - the collector is set to protocol: rfc3164. rsyslog's DEFAULT
#               omfwd template is version-dependent and may emit RFC3339
#               timestamps, which that receiver will not parse. Be explicit.
#   queue     - the collector gets restarted for config changes; without a queue
#               rsyslog drops messages during the restart instead of buffering.
cat > /etc/rsyslog.d/90-first-light.conf <<EOF
*.* action(type="omfwd"
           target="${SYSLOG_HOST}"
           port="${SYSLOG_PORT}"
           protocol="tcp"
           template="RSYSLOG_TraditionalForwardFormat"
           queue.type="LinkedList"
           queue.size="10000"
           action.resumeRetryCount="-1")
EOF

rsyslogd -N1 -f /etc/rsyslog.conf

systemctl restart rsyslog 2>/dev/null || { pkill rsyslogd 2>/dev/null || true; sleep 1; rsyslogd; }

sleep 2
logger -t first-light "syslog forwarding enabled on $(hostname)"
echo "Done. Look for host.name=$(hostname) in SigNoz within ~30s."
echo "Verify auth coverage by opening a NEW ssh session and checking for service.name=sshd."
