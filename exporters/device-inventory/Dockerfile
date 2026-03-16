FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY device_discovery.py .

# Create data directory
RUN mkdir -p /data

# Make script executable
RUN chmod +x device_discovery.py

# Expose Prometheus metrics port
EXPOSE 9005

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:9005/metrics', timeout=5)" || exit 1

# Run discovery
CMD ["python", "-u", "device_discovery.py"]
