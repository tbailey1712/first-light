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

# Patch base rsyslog.conf for container compatibility:
#   imklog   - requires /proc/kmsg, not available in containers
#   imuxsock - conflicts with journald owning the syslog socket
sed -i \
    -e 's|^module(load="imklog"|#module(load="imklog"|' \
    -e 's|^module(load="imuxsock")|module(load="imuxsock" SysSock.Use="off")|' \
    /etc/rsyslog.conf

# Read the journal, so units that log only to journald (sshd on modern Ubuntu)
# are still forwarded.
mkdir -p /var/spool/rsyslog
cat > /etc/rsyslog.d/10-imjournal.conf <<'EOF'
global(workDirectory="/var/spool/rsyslog")
module(load="imjournal" StateFile="imjournal.state")
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
