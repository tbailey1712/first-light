FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy exporter script
COPY qnap_exporter.py .

# Make script executable
RUN chmod +x qnap_exporter.py

# Expose Prometheus metrics port
EXPOSE 9003

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:9003/metrics', timeout=5)" || exit 1

# Run exporter
CMD ["python", "-u", "qnap_exporter.py"]
