#!/bin/bash
set -e

# Start cron daemon (for logrotate)
cron

# Run rsyslog in foreground (writes PID to /var/run/rsyslogd.pid)
exec rsyslogd -n -f /etc/rsyslog.conf -i /var/run/rsyslogd.pid
