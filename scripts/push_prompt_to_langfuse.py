#!/usr/bin/env python3
"""
Push a domain agent prompt to Langfuse with label='production'.

Usage:
    python scripts/push_prompt_to_langfuse.py <prompt_slug>

Example:
    python scripts/push_prompt_to_langfuse.py first-light-dns

Reads the fallback constant from daily_report.py and pushes it to Langfuse.
This is the authoritative path for updating production prompts — never edit
the hardcoded constant and consider that "done".
"""

import sys
import os

# Allow running from repo root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load .env
from dotenv import load_dotenv
load_dotenv()

SLUG_TO_CONSTANT = {
    "first-light-dns":          "DNS_SYSTEM",
    "first-light-firewall-threat": "FIREWALL_THREAT_SYSTEM",
    "first-light-network-flow": "NETWORK_FLOW_SYSTEM",
    "first-light-infrastructure": "INFRASTRUCTURE_SYSTEM",
    "first-light-wireless":     "WIRELESS_SYSTEM",
    "first-light-validator":    "VALIDATOR_SYSTEM",
    "first-light-synthesis":    "SYNTHESIS_SYSTEM",
}


def push_prompt(slug: str) -> None:
    constant_name = SLUG_TO_CONSTANT.get(slug)
    if not constant_name:
        print(f"ERROR: Unknown slug '{slug}'. Known slugs:")
        for s in SLUG_TO_CONSTANT:
            print(f"  {s}")
        sys.exit(1)

    # Import the fallback constant
    import agent.domains.daily_report as dr
    prompt_text = getattr(dr, constant_name, None)
    if not prompt_text:
        print(f"ERROR: Constant '{constant_name}' not found in daily_report.py")
        sys.exit(1)

    # Push to Langfuse
    from agent.langfuse_integration import get_prompt_manager
    manager = get_prompt_manager()
    manager.create_prompt(
        name=slug,
        prompt=prompt_text.strip(),
        labels=["production"],
    )
    print(f"✓ Pushed '{slug}' to Langfuse with label=production")
    print(f"  Source constant: {constant_name}")
    print(f"  Length: {len(prompt_text)} chars")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        print("Available slugs:")
        for s in SLUG_TO_CONSTANT:
            print(f"  {s}")
        sys.exit(1)

    push_prompt(sys.argv[1])
