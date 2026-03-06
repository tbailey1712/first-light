#!/usr/bin/env python
"""
Test DNS Security Domain execution.
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from agent.domains.dns_security import analyze_dns_security

if __name__ == "__main__":
    result = analyze_dns_security(time_range_hours=24)

    print("\n" + "=" * 80)
    print("DOMAIN SUMMARY")
    print("=" * 80)
    print(result.domain_summary)
    print()
    print(f"Total findings: {len(result.critical_findings) + len(result.high_findings) + len(result.medium_findings) + len(result.low_findings)}")
