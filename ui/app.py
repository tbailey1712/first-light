"""
First Light Management UI (S3-05)

FastAPI + Jinja2 + HTMX management interface.
Runs on port 8085.

Features:
- Reports list with view/download
- Trigger on-demand report
- System status (channels, scheduler, Redis)
- Config overview (which integrations are active)
- Optional Basic Auth (set UI_BASIC_AUTH_PASSWORD in .env)

Environment variables:
  UI_BASIC_AUTH_USER      — Basic auth username (default: admin)
  UI_BASIC_AUTH_PASSWORD  — Basic auth password (leave unset to disable auth)
  FIRST_LIGHT_REPORTS_DIR — Where daily reports are stored
"""

import asyncio
import base64
import logging
import os
import re
import secrets
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

logger = logging.getLogger(__name__)

_REPORTS_DIR = Path(os.getenv("FIRST_LIGHT_REPORTS_DIR", "/data/reports")) / "daily"
_TEMPLATES_DIR = Path(__file__).parent / "templates"
_STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="First Light UI", docs_url=None, redoc_url=None)

# Strong references to background tasks so they aren't GC'd mid-execution
_background_tasks: set = set()

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


# ── Optional Basic Auth ──────────────────────────────────────────────────────────

def _check_auth(request: Request) -> None:
    password = os.getenv("UI_BASIC_AUTH_PASSWORD")
    if not password:
        return  # Auth disabled
    username = os.getenv("UI_BASIC_AUTH_USER", "admin")

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Basic "):
        raise HTTPException(
            status_code=401,
            headers={"WWW-Authenticate": "Basic realm=\"First Light\""},
            detail="Authentication required",
        )
    try:
        decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
        req_user, req_pass = decoded.split(":", 1)
    except Exception:
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Basic realm=\"First Light\""})

    if not (secrets.compare_digest(req_user, username) and secrets.compare_digest(req_pass, password)):
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Basic realm=\"First Light\""})


# ── Helpers ──────────────────────────────────────────────────────────────────────

def _list_reports() -> list[dict]:
    """Return metadata for all saved daily reports, newest first."""
    reports = []
    if not _REPORTS_DIR.exists():
        return reports
    for md_file in sorted(_REPORTS_DIR.rglob("*_daily_report.md"), reverse=True):
        stat = md_file.stat()
        date_str = md_file.stem.replace("_daily_report", "")
        reports.append({
            "date": date_str,
            "path": str(md_file),
            "size_kb": round(stat.st_size / 1024, 1),
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
        })
    return reports


def _system_status() -> dict:
    """Return current system status snapshot."""
    from agent.config import get_config

    cfg = get_config()

    # Notification channels — derived from config, not in-process registry
    # (each Docker container has its own memory space; the registry is only
    # populated at scheduler startup, not in the UI process)
    channels = []
    if cfg.telegram_bot_token and cfg.telegram_chat_id:
        channels.append("telegram")
    if cfg.slack_webhook_url or cfg.slack_bot_token:
        channels.append("slack")

    # Redis connectivity
    redis_ok = False
    try:
        import redis
        r = redis.Redis.from_url(
            os.getenv("REDIS_URL", "redis://fl-redis:6379/0"),
            socket_connect_timeout=2, socket_timeout=2,
        )
        r.ping()
        redis_ok = True
    except Exception:
        pass

    # Active integrations (based on config presence)
    integrations = {
        "adguard": bool(cfg.adguard_host),
        "telegram": bool(cfg.telegram_bot_token),
        "slack": bool(os.getenv("SLACK_WEBHOOK_URL") or os.getenv("SLACK_BOT_TOKEN")),
        "qnap": bool(cfg.qnap_api_url),
        "proxmox": True,  # always queried via ClickHouse
        "threat_intel": bool(
            os.getenv("ABUSEIPDB_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
        ),
        "langfuse": bool(os.getenv("LANGFUSE_SECRET_KEY")),
    }

    return {
        "redis": redis_ok,
        "notification_channels": channels,
        "integrations": integrations,
        "reports_dir": str(_REPORTS_DIR),
        "report_count": len(_list_reports()),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ── Routes ───────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, _: None = Depends(_check_auth)):
    reports = _list_reports()[:10]
    status = _system_status()
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "reports": reports, "status": status},
    )


@app.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request, _: None = Depends(_check_auth)):
    reports = _list_reports()
    return templates.TemplateResponse(
        "reports.html",
        {"request": request, "reports": reports},
    )


@app.get("/reports/{date}", response_class=HTMLResponse)
async def view_report(date: str, request: Request, _: None = Depends(_check_auth)):
    """View a specific report by date (YYYY-MM-DD)."""
    if not _DATE_RE.match(date):
        raise HTTPException(status_code=400, detail="Invalid date format")
    for report in _list_reports():
        if report["date"] == date:
            report_path = Path(report["path"]).resolve()
            if not str(report_path).startswith(str(_REPORTS_DIR.resolve())):
                raise HTTPException(status_code=403)
            content = report_path.read_text()
            return templates.TemplateResponse(
                "report_view.html",
                {"request": request, "date": date, "content": content, "report": report},
            )
    raise HTTPException(status_code=404, detail="Report not found")


@app.get("/reports/{date}/raw", response_class=PlainTextResponse)
async def download_report(date: str, _: None = Depends(_check_auth)):
    """Download raw report markdown."""
    if not _DATE_RE.match(date):
        raise HTTPException(status_code=400, detail="Invalid date format")
    for report in _list_reports():
        if report["date"] == date:
            report_path = Path(report["path"]).resolve()
            if not str(report_path).startswith(str(_REPORTS_DIR.resolve())):
                raise HTTPException(status_code=403)
            content = report_path.read_text()
            return PlainTextResponse(
                content,
                headers={"Content-Disposition": f"attachment; filename={date}_daily_report.md"},
            )
    raise HTTPException(status_code=404, detail="Report not found")


@app.get("/status", response_class=HTMLResponse)
async def status_page(request: Request, _: None = Depends(_check_auth)):
    status = _system_status()
    return templates.TemplateResponse(
        "status.html",
        {"request": request, "status": status},
    )


@app.get("/api/status")
async def api_status(_: None = Depends(_check_auth)):
    """JSON status endpoint for HTMX polling."""
    return JSONResponse(_system_status())


@app.post("/api/report/trigger")
async def trigger_report(request: Request, _: None = Depends(_check_auth)):
    """Trigger an on-demand report (runs in background)."""
    async def _run():
        from agent.reports.daily_threat_assessment import generate_daily_report, send_report_notification
        try:
            report = await generate_daily_report()
            await send_report_notification(report)
            logger.info("On-demand report triggered from UI: %s", report["report_path"])
        except Exception as e:
            logger.error("On-demand report failed: %s", e, exc_info=True)

    # Keep a strong reference so the task isn't GC'd before it completes
    task = asyncio.create_task(_run())
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return JSONResponse({"status": "triggered", "message": "Report generation started"})


@app.get("/health")
async def health():
    return {"status": "ok"}
