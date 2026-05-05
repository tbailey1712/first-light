"""
Priority alert scanner.

Scans the final daily report text against user-defined alert patterns in
docs/PRIORITY_ALERTS.md. When a match is found, fires a high-priority
Pushover notification immediately.

Alert definitions live in docs/PRIORITY_ALERTS.md — edit that file to
add/remove alert triggers without code changes.
"""

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_ALERTS_FILE = Path(__file__).parent.parent / "docs" / "PRIORITY_ALERTS.md"


@dataclass
class AlertRule:
    name: str
    keywords: list[str]
    title: str
    priority: str  # "high" or "emergency"


def _parse_alert_rules() -> list[AlertRule]:
    """Parse PRIORITY_ALERTS.md into structured alert rules."""
    if not _ALERTS_FILE.exists():
        logger.warning("PRIORITY_ALERTS.md not found at %s", _ALERTS_FILE)
        return []

    text = _ALERTS_FILE.read_text()
    rules: list[AlertRule] = []
    current_name: Optional[str] = None
    current_keywords: list[str] = []
    current_title: str = ""
    current_priority: str = "high"

    for line in text.splitlines():
        line = line.strip()

        # New alert block: "- **Name**"
        m = re.match(r'^-\s+\*\*(.+?)\*\*', line)
        if m:
            # Save previous rule if complete
            if current_name and current_keywords:
                rules.append(AlertRule(
                    name=current_name,
                    keywords=current_keywords,
                    title=current_title or current_name,
                    priority=current_priority,
                ))
            current_name = m.group(1)
            current_keywords = []
            current_title = ""
            current_priority = "high"
            continue

        # Keywords line: "- keywords: `word1`, `word2`"
        m = re.match(r'^-\s+keywords?:\s*(.+)', line, re.IGNORECASE)
        if m and current_name:
            # Extract backtick-delimited keywords
            current_keywords = [k.strip().strip('`') for k in m.group(1).split(',')]
            current_keywords = [k for k in current_keywords if k]
            continue

        # Title line: "- title: Something"
        m = re.match(r'^-\s+title:\s*(.+)', line, re.IGNORECASE)
        if m and current_name:
            current_title = m.group(1).strip()
            continue

        # Priority line: "- priority: high|emergency"
        m = re.match(r'^-\s+priority:\s*(.+)', line, re.IGNORECASE)
        if m and current_name:
            current_priority = m.group(1).strip().lower()
            continue

    # Save last rule
    if current_name and current_keywords:
        rules.append(AlertRule(
            name=current_name,
            keywords=current_keywords,
            title=current_title or current_name,
            priority=current_priority,
        ))

    logger.info("Loaded %d priority alert rules", len(rules))
    return rules


@dataclass
class TriggeredAlert:
    rule: AlertRule
    context: str  # Relevant lines from the report


def check_priority_alerts(report_text: str) -> list[TriggeredAlert]:
    """Check report text against all priority alert rules.

    Returns list of TriggeredAlerts with context extracted from the report.
    """
    rules = _parse_alert_rules()
    triggered: list[TriggeredAlert] = []
    report_lower = report_text.lower()
    report_lines = report_text.splitlines()

    for rule in rules:
        matched_kw = next((kw for kw in rule.keywords if kw.lower() in report_lower), None)
        if matched_kw:
            # Extract lines containing the matched keyword for context
            context_lines = [
                ln.strip() for ln in report_lines
                if matched_kw.lower() in ln.lower() and ln.strip()
            ]
            # Cap at 3 lines, 300 chars total
            context = "\n".join(context_lines[:3])[:300]
            triggered.append(TriggeredAlert(rule=rule, context=context))
            logger.warning("Priority alert triggered: %s", rule.name)

    return triggered


async def fire_priority_alerts(report_text: str) -> int:
    """Scan report for priority alerts and send Pushover notifications.

    Returns number of alerts fired.
    """
    from agent.notifications.pushover import build_pushover_channel

    triggered = check_priority_alerts(report_text)
    if not triggered:
        return 0

    pushover = build_pushover_channel()
    if not pushover:
        logger.error("Priority alerts triggered but Pushover not configured!")
        return 0

    import httpx

    _PUSHOVER_URL = "https://api.pushover.net/1/messages.json"
    _PRI_MAP = {"high": 1, "emergency": 2}

    fired = 0
    for alert in triggered:
        priority = _PRI_MAP.get(alert.rule.priority, 1)
        message = alert.context if alert.context else alert.rule.name
        payload = {
            "token": pushover._token,
            "user": pushover._user,
            "title": f"🚨 {alert.rule.title}",
            "message": message,
            "priority": priority,
            "sound": "siren",
        }
        # Emergency priority requires retry/expire params
        if priority == 2:
            payload["retry"] = 60    # retry every 60s
            payload["expire"] = 600  # stop after 10min

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(_PUSHOVER_URL, data=payload)
            if resp.status_code == 200:
                logger.info("Priority alert sent: %s (priority=%s)", alert.rule.title, alert.rule.priority)
                fired += 1
            else:
                logger.error("Priority alert Pushover failed: %s — %s", resp.status_code, resp.text[:200])
        except Exception as e:
            logger.error("Priority alert send error: %s", e)

    return fired
