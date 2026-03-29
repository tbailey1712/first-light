FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all application source
# agent/ — scheduler, tools, graph, notifications
# bot/   — telegram and slack bots
# ui/    — management FastAPI app
COPY agent/ ./agent/
COPY bot/ ./bot/
COPY ui/ ./ui/

HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "from apscheduler.schedulers.asyncio import AsyncIOScheduler; print('ok')" || exit 1

CMD ["python", "-m", "agent.scheduler"]
