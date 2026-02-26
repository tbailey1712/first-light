#!/bin/bash
# Setup automated disk monitoring and cleanup for First Light

set -e

echo "Setting up First Light disk monitoring..."

# Make scripts executable
chmod +x /opt/first-light/scripts/monitor_disk.sh
chmod +x /opt/first-light/scripts/emergency_cleanup.sh

# Add cron jobs
(crontab -l 2>/dev/null | grep -v "first-light"; cat <<EOF
# First Light disk monitoring (every 15 minutes)
*/15 * * * * /opt/first-light/scripts/monitor_disk.sh

# First Light auto-cleanup (daily at 3am, keep 7 days)
0 3 * * * /opt/first-light/scripts/emergency_cleanup.sh 7 >> /var/log/first-light-cleanup.log 2>&1
EOF
) | crontab -

echo "✅ Cron jobs installed:"
echo "  - Disk monitoring: every 15 minutes"
echo "  - Auto-cleanup: daily at 3am (7-day retention)"

# Create log directory
sudo mkdir -p /var/log
sudo touch /var/log/first-light-disk-monitor.log
sudo touch /var/log/first-light-cleanup.log

# Set permissions
sudo chmod 644 /var/log/first-light-*.log

echo ""
echo "✅ Setup complete!"
echo ""
echo "To view logs:"
echo "  sudo tail -f /var/log/first-light-disk-monitor.log"
echo "  sudo tail -f /var/log/first-light-cleanup.log"
echo ""
echo "To test disk monitoring now:"
echo "  /opt/first-light/scripts/monitor_disk.sh"
