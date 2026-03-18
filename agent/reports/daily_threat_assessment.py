#!/usr/bin/env python3
"""
Daily Threat Assessment Report Generator

Runs daily at 08:00 to analyze the past 24 hours and generate a security report.
"""

import asyncio
import json
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any

from langchain_core.messages import HumanMessage

from agent.graph import get_agent
from agent.reports.database import ReportsDatabase
import os


# Use environment variable for reports dir, default to project dir for testing
REPORTS_BASE = os.getenv("FIRST_LIGHT_REPORTS_DIR", str(Path(__file__).parent.parent.parent / "reports"))
REPORTS_DIR = Path(REPORTS_BASE) / "daily"


def ensure_directories():
    """Create report directory structure."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def get_report_path(date: str) -> Path:
    """Get file path for a report."""
    year, month, day = date.split('-')
    report_dir = REPORTS_DIR / year / month
    report_dir.mkdir(parents=True, exist_ok=True)
    return report_dir / f"{date}_daily_report.md"


def get_metrics_path(date: str) -> Path:
    """Get file path for metrics JSON."""
    year, month, day = date.split('-')
    report_dir = REPORTS_DIR / year / month
    return report_dir / f"{date}_metrics.json"


async def generate_daily_report() -> Dict[str, Any]:
    """Generate daily threat assessment report using AI agent."""
    
    print("🔍 Generating Daily Threat Assessment Report")
    print(f"📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Initialize agent and database
    agent = get_agent()
    db = ReportsDatabase()
    
    # Generate report ID
    report_id = str(uuid.uuid4())
    report_date = datetime.now().strftime('%Y-%m-%d')
    
    # Construct analysis prompt for the AI agent
    analysis_prompt = """Generate a comprehensive daily threat assessment report for the past 24 hours.

Use these tools in this order:
1. query_threat_intel_summary(hours=24) — START HERE. This shows confirmed threats hitting the firewall with reputation scores.
2. query_security_summary(hours=24) — raw firewall block counts and ntopng alerts
3. For any IPs with threat_score > 50 from step 1, call lookup_ip_threat_intel(ip) for full details
4. query_adguard_block_rates(hours=24) — DNS filtering metrics
5. query_infrastructure_events(hours=24) — Docker/HA/Proxmox health
6. query_wireless_health(hours=24) — WiFi issues

Include the following sections:

## Executive Summary
2-3 sentences: Overall security posture, any confirmed malicious IPs, all-clear or action required.

## Threat Intelligence Highlights
- Confirmed malicious IPs blocked (threat_score > 50): count, top IPs with scores
- High-confidence threats: IP, score, country, ASN, what they tried to do (target port/protocol)
- Any IPs with AbuseIPDB score > 50 or VirusTotal malicious vendors > 2: call them out specifically
- Enrichment coverage: X of Y blocked IPs enriched

## Security Metrics (24h)
- Total firewall blocks, unique attacker IPs
- DNS blocks (total, high-risk count from AdGuard)
- ntopng alerts (if any)

## Infrastructure Health
- Docker container health
- Home Assistant errors (if any)

## Notable Events
Only include if genuinely notable (confirmed malicious actor, unusual pattern, cross-VLAN traffic).
Cross-VLAN traffic from Camera VLAN (3) or Validator VLAN (4) is CRITICAL.

## Action Items
Only include if actions are ACTUALLY required:
- CRITICAL: Block this IP, immediate investigation needed
- WARNING: Monitor this pattern, review within 24h
- INFO: Low priority

Format: clean Markdown, emojis for scanning (🛡️ 🚨 ✅ ⚠️ 🔴 🟡 🟢), specific IPs/counts/scores.
Be concise. Skip sections that have nothing to report.
"""
    
    print("\n🤖 Querying AI agent for analysis...")
    
    # Stream agent response
    config = {"configurable": {"thread_id": f"daily-report-{report_date}"}}
    
    full_response = ""
    async for event in agent.astream(
        {"messages": [HumanMessage(content=analysis_prompt)]},
        config=config,
        stream_mode="values"
    ):
        if "messages" in event and event["messages"]:
            last_msg = event["messages"][-1]
            if hasattr(last_msg, "content") and last_msg.content:
                if not hasattr(last_msg, "tool_calls") or not last_msg.tool_calls:
                    full_response = last_msg.content
    
    # Extract metrics from response (basic parsing)
    # In a production system, you'd ask the agent to also return structured JSON
    metrics = extract_metrics_from_report(full_response)
    
    # Save to database
    db.save_daily_metrics(report_id, report_date, metrics)
    
    # Build final report with header
    report_header = f"""# First Light - Daily Threat Assessment
**Date:** {report_date}
**Report ID:** {report_id}
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

---

"""
    
    full_report = report_header + full_response
    
    # Save report files
    report_path = get_report_path(report_date)
    metrics_path = get_metrics_path(report_date)
    
    report_path.write_text(full_report)
    print(f"\n✅ Report saved: {report_path}")
    
    # Save metrics JSON
    metrics_data = {
        "report_id": report_id,
        "report_type": "daily",
        "date": report_date,
        "generated_at": datetime.now().isoformat(),
        "metrics": metrics,
        "report_path": str(report_path),
    }
    metrics_path.write_text(json.dumps(metrics_data, indent=2))
    print(f"✅ Metrics saved: {metrics_path}")
    
    return {
        "report_id": report_id,
        "date": report_date,
        "report_path": str(report_path),
        "metrics": metrics,
        "report_text": full_report,
    }


def extract_metrics_from_report(report_text: str) -> Dict[str, Any]:
    """Extract key metrics from the report text.
    
    This is a simple parser. In production, you'd ask the agent to return
    structured JSON alongside the markdown report.
    """
    # For MVP, return empty metrics dict
    # Will be populated by database queries or structured agent output
    return {
        "firewall_blocks": 0,
        "dns_blocks": 0,
        "dns_high_risk_blocks": 0,
        "flow_alerts_critical": 0,
        "flow_alerts_warning": 0,
        "ssh_failures": 0,
        "unique_attacker_ips": 0,
        "disk_usage_percent": 0.0,
        "disk_used_gb": 0.0,
        "container_restarts": 0,
    }


async def send_report_notification(report: Dict[str, Any]):
    """Send report via Telegram."""
    from agent.config import get_config
    import httpx

    config = get_config()

    # Read the full report
    report_text = report['report_text']

    # Truncate if too long for Telegram (max 4096 chars)
    if len(report_text) > 4000:
        # Send executive summary + link to full report
        lines = report_text.split('\n')
        summary = '\n'.join(lines[:50])  # First 50 lines
        message = f"{summary}\n\n... Report truncated ...\n\n📄 Full report: {report['report_path']}"
    else:
        message = report_text

    # Send via Telegram
    try:
        telegram_url = f"https://api.telegram.org/bot{config.telegram_bot_token}/sendMessage"

        async with httpx.AsyncClient() as client:
            response = await client.post(
                telegram_url,
                json={
                    "chat_id": config.telegram_chat_id,
                    "text": message,
                    "parse_mode": "Markdown",
                    "disable_web_page_preview": True,
                }
            )

            if response.status_code == 200:
                print(f"\n✅ Report sent to Telegram chat {config.telegram_chat_id}")
            else:
                print(f"\n⚠️ Telegram send failed: {response.status_code}")
                print(f"Response: {response.text}")

    except Exception as e:
        print(f"\n⚠️ Error sending to Telegram: {e}")
        print(f"📄 Report saved locally: {report['report_path']}")

    print(f"\n📄 Report also saved to: {report['report_path']}")


async def main():
    """Main entry point."""
    ensure_directories()
    
    try:
        report = await generate_daily_report()
        await send_report_notification(report)
        print("\n✅ Daily threat assessment complete!")
        
    except Exception as e:
        print(f"\n❌ Error generating report: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    asyncio.run(main())
