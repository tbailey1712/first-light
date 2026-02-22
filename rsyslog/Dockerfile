# Custom rsyslog container with all necessary modules
# Based on Debian to ensure omfile and omfwd modules are available

FROM debian:12-slim

# Install rsyslog with all standard modules
# Note: omfile is built-in, omfwd requires the main rsyslog package
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    rsyslog \
    rsyslog-relp \
    && rm -rf /var/lib/apt/lists/*

# The omfwd module should be built-in to rsyslog on Debian,
# but we need to ensure the configuration doesn't try to load it explicitly

# Create log directory
RUN mkdir -p /var/log/remote && chmod 755 /var/log/remote

# Copy configuration
COPY rsyslog.conf /etc/rsyslog.conf

# Expose syslog ports
EXPOSE 514/udp 514/tcp

# Run rsyslog in foreground
CMD ["rsyslogd", "-n", "-f", "/etc/rsyslog.conf"]
