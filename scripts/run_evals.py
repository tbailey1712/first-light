#!/usr/bin/env python3
"""
CLI entrypoint for the First Light eval agent.

Usage:
    python scripts/run_evals.py [--days N]

Runs the full eval lifecycle: collect traces, store dataset items,
run experiments (replay + judge), detect regressions, post Slack summary.
"""

import argparse
import logging
import sys

from dotenv import load_dotenv


def main():
    load_dotenv(override=True)

    parser = argparse.ArgumentParser(description="First Light eval agent")
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="Number of days of traces to look back (default: 7)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable DEBUG logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    from agent.evals.eval_agent import run_eval_agent

    result = run_eval_agent(days=args.days)

    # Print summary to stdout
    scores = result.get("experiment_scores", {})
    if scores:
        print("\n" + "=" * 60)
        print("EVAL RESULTS")
        print("=" * 60)
        for exp_id, s in scores.items():
            print(f"\n  {exp_id}:")
            print(f"    completeness:       {s.get('completeness', 0):.3f}")
            print(f"    actionability:      {s.get('actionability', 0):.3f}")
            print(f"    severity_accuracy:  {s.get('severity_accuracy', 0):.3f}")
            print(f"    format:             {s.get('format', 0):.3f}")
            print(f"    false_positive_rate: {s.get('false_positive_rate', 0):.3f}")
            print(f"    composite:          {s.get('composite', 0):.3f}")

        regressions = result.get("regressions", [])
        if regressions:
            print("\nREGRESSIONS:")
            for r in regressions:
                flags = []
                if r["regressed"]:
                    flags.append("regressed")
                if r["below_minimum"]:
                    flags.append("below minimum")
                print(f"  {r['dimension']}: {r['current']:.3f} (delta={r['delta']:+.3f}) [{', '.join(flags)}]")
        else:
            print("\nNo regressions detected.")

        champion = result.get("new_champion")
        if champion:
            print(f"\nNew champion: {champion}")
        print("=" * 60)
    else:
        print("No experiment results produced.")

    sys.exit(0 if not result.get("regressions") else 1)


if __name__ == "__main__":
    main()
