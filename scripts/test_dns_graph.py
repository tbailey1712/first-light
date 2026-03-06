#!/usr/bin/env python
"""
Test DNS Security Graph with parallel execution.
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from agent.graphs.dns_security_graph import analyze_dns_security_parallel

if __name__ == "__main__":
    import time
    start = time.time()

    result = analyze_dns_security_parallel(time_range_hours=24)

    elapsed = time.time() - start

    print("\n" + "=" * 80)
    print("DOMAIN SUMMARY")
    print("=" * 80)
    if result.get("supervisor_outputs"):
        print(result["supervisor_outputs"][0].domain_summary)
    print()
    print(f"Total findings: {result.get('total_findings', 0)}")
    print(f"Critical findings: {result.get('critical_count', 0)}")
    print(f"Execution time: {elapsed:.1f}s")
