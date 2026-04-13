FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy enricher service and threat intel module
COPY enricher.py threat_intel.py ./

# Create cache directory
RUN mkdir -p /data/threat_intel_cache

# Expose Prometheus metrics port
EXPOSE 9006

# Health check
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:9006', timeout=2)" || exit 1

# Run enricher
CMD ["python", "-u", "enricher.py"]
