"""
Shared context loader for domain agents.

Reads docs/KNOWN_ISSUES.md and docs/MONITOR.md, filters items by domain tag,
and returns a formatted context block to prepend to agent system prompts.

Domain tags: [firewall_threat, dns_security, infrastructure, ...] control which
agents see each item. Items with no tag apply to all agents.
"""

import logging
import re
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)

_DOCS_DIR = Path(__file__).parent.parent / "docs"

# Matches [domain1, domain2] anywhere in a line
_TAG_RE = re.compile(r'\[([^\]]+)\]')


def _parse_items(filepath: Path, domain: str | None) -> list[str]:
    """Parse bullet items from a markdown file, filtering by domain tag."""
    try:
        text = filepath.read_text()
    except FileNotFoundError:
        logger.debug("Shared context file not found: %s", filepath)
        return []

    items = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("- "):
            continue

        tag_match = _TAG_RE.search(stripped)
        if tag_match and domain:
            tags = [t.strip().lower() for t in tag_match.group(1).split(",")]
            if domain.lower() not in tags and "all" not in tags:
                continue
            # Strip the tag from output
            clean = _TAG_RE.sub("", stripped).strip()
            # Clean up double spaces left after tag removal
            clean = re.sub(r'  +', ' ', clean)
        elif tag_match and not domain:
            # No domain filter — include everything, strip tags
            clean = _TAG_RE.sub("", stripped).strip()
            clean = re.sub(r'  +', ' ', clean)
        else:
            # No tag — applies to all domains
            clean = stripped

        if clean and clean != "-":
            items.append(clean)

    return items


@lru_cache(maxsize=16)
def load_shared_context(domain: str | None = None) -> str:
    """Load and filter shared context for a specific domain agent.

    Args:
        domain: Domain name (e.g. "firewall_threat", "dns_security").
                Pass None to get all items unfiltered (for synthesis).

    Returns:
        Formatted context block to prepend to system prompt.
        Empty string if no files found or no matching items.
    """
    known = _parse_items(_DOCS_DIR / "KNOWN_ISSUES.md", domain)
    monitor = _parse_items(_DOCS_DIR / "MONITOR.md", domain)

    if not known and not monitor:
        return ""

    sections = []
    sections.append("=== SHARED OPERATIONAL CONTEXT ===")

    if known:
        sections.append("")
        sections.append("KNOWN ISSUES — do NOT flag these as findings unless the stated condition changes:")
        for item in known:
            sections.append(item)

    if monitor:
        sections.append("")
        sections.append("ACTIVE MONITORING — report on these ONLY when status changes:")
        for item in monitor:
            sections.append(item)

    sections.append("")
    sections.append("=== END SHARED CONTEXT ===")

    result = "\n".join(sections)
    token_estimate = len(result.split())
    logger.info("Shared context for %s: %d items, ~%d tokens",
                domain or "all", len(known) + len(monitor), token_estimate)

    return result
