FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY agent/ /app/agent/
COPY mcp_servers/ /app/mcp_servers/

# Expose MCP server port
EXPOSE 8080

# Run FastMCP server
CMD ["python", "mcp_servers/dns_security.py"]
