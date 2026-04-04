#!/usr/bin/env python3
"""
Integration tests for all new First Light agent tools.

Tests real connectivity, authentication, and data format for every new tool
added in the April 2026 enhancement sprint. NO mocks — all tests hit live
infrastructure.

Run from the project root on the Docker host (or with .env pointing to live services):
    cd /opt/first-light && python3 scripts/test_new_tools.py

Exit codes:
    0 — all tests passed (or skipped due to missing config)
    1 — one or more tests failed (connection error, auth error, bad data)
"""

import json
import os
import sys
import time
import traceback
from typing import Callable, Optional

# Ensure agent package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load .env before importing agent modules
from dotenv import load_dotenv
load_dotenv()


# ── Test harness ───────────────────────────────────────────────────────────────

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
SKIP = "\033[93m⊘\033[0m"
WARN = "\033[93m⚠\033[0m"

results = {"pass": 0, "fail": 0, "skip": 0}


# Errors that indicate a service is only reachable inside Docker (expected locally)
_DOCKER_INTERNAL_ERRORS = (
    "nodename nor servname provided",
    "Name or service not known",
    "Connection refused",
    "Could not reach",
)


def _is_docker_internal_error(msg: str) -> bool:
    return any(e in msg for e in _DOCKER_INTERNAL_ERRORS)


def run_test(
    name: str,
    fn: Callable[[], str],
    required_keys: Optional[list] = None,
    skip_if_missing: Optional[str] = None,
    expect_not_error: bool = True,
    docker_internal: bool = False,
) -> Optional[dict]:
    """
    Run a single tool test.

    Args:
        name: Display name for the test
        fn: Callable that returns the tool's JSON output string
        required_keys: Keys that must exist in the returned JSON
        skip_if_missing: Environment variable name — skip test if this is not set
        expect_not_error: If True, fail if returned JSON has an 'error' key
    """
    if skip_if_missing and not os.environ.get(skip_if_missing):
        print(f"  {SKIP} {name} — skipped (${skip_if_missing} not set)")
        results["skip"] += 1
        return None

    t0 = time.time()
    try:
        raw = fn()
    except Exception as e:
        elapsed = time.time() - t0
        print(f"  {FAIL} {name} — EXCEPTION after {elapsed:.1f}s: {e}")
        traceback.print_exc()
        results["fail"] += 1
        return None

    elapsed = time.time() - t0

    try:
        data = json.loads(raw)
    except Exception:
        # Some tools return plain text errors when the service is unreachable
        if docker_internal and _is_docker_internal_error(raw):
            print(f"  {SKIP} {name} — Docker-internal service unreachable (run on Docker host to test)")
            results["skip"] += 1
            return None
        print(f"  {FAIL} {name} — response is not valid JSON ({elapsed:.1f}s):")
        print(f"         {raw[:200]}")
        results["fail"] += 1
        return None

    if isinstance(data, dict) and "error" in data:
        error_msg = str(data["error"])
        if docker_internal and _is_docker_internal_error(error_msg):
            print(f"  {SKIP} {name} — Docker-internal service unreachable (run on Docker host to test)")
            results["skip"] += 1
            return data
        if expect_not_error:
            print(f"  {FAIL} {name} — tool returned error ({elapsed:.1f}s): {error_msg}")
            results["fail"] += 1
            return data

    if required_keys:
        missing = [k for k in required_keys if k not in data]
        if missing:
            print(f"  {FAIL} {name} — missing keys {missing} ({elapsed:.1f}s)")
            results["fail"] += 1
            return data

    print(f"  {PASS} {name} ({elapsed:.1f}s)")
    results["pass"] += 1
    return data


def section(title: str):
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")


# ── Tool imports ───────────────────────────────────────────────────────────────

def main():
    print("\nFirst Light — New Tools Integration Test")
    print("=" * 60)
    print("Tests hit LIVE infrastructure. No mocks.\n")

    # ── 1. Cloudflare DNS records + Access apps (TOOL-3, TOOL-4) ──────────────
    section("Cloudflare: DNS Records + Access Apps")

    from agent.tools.cloudflare_tools import (
        query_cloudflare_dns_records,
        query_cloudflare_access_apps,
    )

    d = run_test(
        "query_cloudflare_dns_records",
        lambda: query_cloudflare_dns_records.invoke({}),
        required_keys=["total", "records"],
        skip_if_missing="CLOUDFLARE_API_TOKEN",
    )
    if d:
        total = d.get("total", 0)
        print(f"         → {total} DNS records returned")
        if total == 0:
            print(f"  {WARN} No DNS records — zone may be empty or ZONE_ID incorrect")

    d = run_test(
        "query_cloudflare_access_apps",
        lambda: query_cloudflare_access_apps.invoke({}),
        required_keys=["total", "apps"],
        skip_if_missing="CLOUDFLARE_ACCOUNT_ID",
    )
    if d:
        total = d.get("total", 0)
        print(f"         → {total} Access apps configured")

    # ── 2. pfSense XML-RPC (TOOL-1, TOOL-2) ───────────────────────────────────
    section("pfSense: Firewall Rules + DNS Overrides (XML-RPC)")

    from agent.tools.pfsense_tools import (
        query_pfsense_firewall_rules,
        query_pfsense_dns_overrides,
    )

    d = run_test(
        "query_pfsense_firewall_rules",
        lambda: query_pfsense_firewall_rules.invoke({}),
        required_keys=["nat_rules", "nat_rule_count"],
        skip_if_missing="PFSENSE_API_KEY",  # skip if creds not set
    )
    if d:
        nat = d.get("nat_rule_count", 0)
        fw = d.get("firewall_rule_count", "?")
        print(f"         → {nat} NAT rules, {fw} firewall rules")

    d = run_test(
        "query_pfsense_dns_overrides",
        lambda: query_pfsense_dns_overrides.invoke({}),
        required_keys=["total", "host_overrides"],
        skip_if_missing="PFSENSE_API_KEY",
    )
    if d:
        print(f"         → {d.get('total', 0)} DNS host overrides")

    # ── 3. CrowdSec (TOOL-7) ──────────────────────────────────────────────────
    section("CrowdSec: Metrics + Decisions")

    from agent.tools.crowdsec import (
        query_crowdsec_alerts,
        query_crowdsec_decisions,
        query_crowdsec_metrics,
    )

    d = run_test(
        "query_crowdsec_alerts",
        lambda: query_crowdsec_alerts.invoke({"limit": 10}),
        required_keys=["total"],
        skip_if_missing="CROWDSEC_MACHINE_ID",
        docker_internal=True,  # fl-crowdsec:8080 only reachable inside Docker
    )

    d = run_test(
        "query_crowdsec_decisions",
        lambda: query_crowdsec_decisions.invoke({"limit": 10}),
        required_keys=["total", "decisions"],
        skip_if_missing="CROWDSEC_API_KEY",
        docker_internal=True,  # fl-crowdsec:8080 only reachable inside Docker
    )
    if d and "error" not in d:
        print(f"         → {d.get('total', 0)} active decisions (bans)")

    # Prometheus metrics only reachable from Docker host (fl-crowdsec:6060)
    d = run_test(
        "query_crowdsec_metrics (Prometheus — Docker host only)",
        lambda: query_crowdsec_metrics.invoke({}),
        required_keys=["active_decisions"],
        docker_internal=True,
    )
    if d and "error" not in d:
        print(f"         → {d.get('active_decisions', '?')} active decisions, "
              f"{d.get('total_alerts', '?')} total alerts")
        sources = d.get("sources", [])
        for s in sources[:5]:
            print(f"           source={s.get('source')} read={s.get('lines_read')} "
                  f"parsed={s.get('lines_parsed')} rate={s.get('parse_rate_pct')}%")

    # ── 4. Proxmox VM Configs (TOOL-8) ────────────────────────────────────────
    section("Proxmox: VM/CT Configuration")

    from agent.tools.proxmox_tools import query_proxmox_vm_configs

    d = run_test(
        "query_proxmox_vm_configs",
        lambda: query_proxmox_vm_configs.invoke({}),
        required_keys=["node", "vms", "containers", "backup_jobs"],
        skip_if_missing="PROXMOX_HOST",
    )
    if d:
        vm_count = len(d.get("vms", []))
        ct_count = len(d.get("containers", []))
        job_count = len(d.get("backup_jobs", []))
        print(f"         → {vm_count} VMs, {ct_count} containers, {job_count} backup jobs")

        # Check for VMs without backup jobs
        all_job_vmids = set()
        for job in d.get("backup_jobs", []):
            vmids = str(job.get("vmids", "all"))
            if vmids == "all":
                all_job_vmids = {"all"}
                break
            all_job_vmids.update(vmids.split(","))

        if "all" not in all_job_vmids:
            vm_ids = {str(v.get("vmid")) for v in d.get("vms", [])}
            ct_ids = {str(c.get("ctid")) for c in d.get("containers", [])}
            not_backed_up = (vm_ids | ct_ids) - all_job_vmids
            if not_backed_up:
                print(f"  {WARN} IDs not in any backup job: {not_backed_up}")

    # ── 5. PBS Prune Policies (TOOL-9) ────────────────────────────────────────
    section("PBS: Prune / Retention Policies")

    from agent.tools.pbs import query_pbs_prune_policies

    d = run_test(
        "query_pbs_prune_policies",
        lambda: query_pbs_prune_policies.invoke({}),
        required_keys=["datastores"],
        skip_if_missing="PBS_TOKEN_SECRET",
    )
    if d:
        for ds in d.get("datastores", []):
            name = ds.get("datastore", "?")
            if "error" in ds:
                print(f"  {WARN} {name}: {ds['error']}")
            else:
                print(f"         → {name}: keep_last={ds.get('keep_last')} "
                      f"keep_daily={ds.get('keep_daily')} "
                      f"keep_weekly={ds.get('keep_weekly')} "
                      f"schedule={ds.get('prune_schedule')}")

    # ── 6. AdGuard Direct API (TOOL-5, TOOL-6, DG-2, DG-4) ──────────────────
    section("AdGuard: Per-Client Query Log (direct API)")

    from agent.tools.adguard_tools import (
        query_adguard_client_blocked_domains,
        query_adguard_nxdomain_clients,
        query_adguard_custom_rules,
    )

    # Test with a connectivity check first (custom rules — lightweight)
    d = run_test(
        "query_adguard_custom_rules (connectivity check)",
        lambda: query_adguard_custom_rules.invoke({}),
        required_keys=["total_custom_rules"],
        skip_if_missing="ADGUARD_USERNAME",  # skip if creds not set
    )
    if d:
        print(f"         → {d.get('total_custom_rules', 0)} custom rules, "
              f"{len(d.get('allowlist_rules', []))} allowlist entries")

    d = run_test(
        "query_adguard_nxdomain_clients",
        lambda: query_adguard_nxdomain_clients.invoke({"limit": 200, "top_n": 10}),
        required_keys=["entries_scanned", "total_nxdomain", "top_clients_by_nxdomain"],
        skip_if_missing="ADGUARD_USERNAME",
    )
    if d:
        print(f"         → scanned {d.get('entries_scanned', 0)} entries, "
              f"{d.get('total_nxdomain', 0)} NXDomain responses")
        for c in d.get("top_clients_by_nxdomain", [])[:3]:
            print(f"           {c['client_ip']}: {c['nxdomain_count']} NXDomains")

    d = run_test(
        "query_adguard_client_blocked_domains (192.168.1.1 sample)",
        lambda: query_adguard_client_blocked_domains.invoke({
            "client_ip": "192.168.1.1",
            "limit": 50,
        }),
        required_keys=["client_ip", "total_blocked", "top_blocked_domains"],
        skip_if_missing="ADGUARD_USERNAME",
    )
    if d:
        print(f"         → {d.get('total_blocked', 0)} blocked queries for test client")

    # ── 7. UniFi (TOOL-10, TOOL-11) ───────────────────────────────────────────
    section("UniFi: Client List + AP Stats")

    from agent.tools.unifi_tools import query_unifi_clients, query_unifi_ap_stats

    d = run_test(
        "query_unifi_clients",
        lambda: query_unifi_clients.invoke({"include_inactive": False}),
        required_keys=["total_clients", "clients"],
        skip_if_missing="UNIFI_USERNAME",  # skip if creds not set
    )
    if d:
        total = d.get("total_clients", 0)
        auth_fails = d.get("auth_failure_clients", [])
        print(f"         → {total} connected clients")
        if auth_fails:
            print(f"  {WARN} {len(auth_fails)} clients with auth failures:")
            for c in auth_fails[:5]:
                print(f"           MAC={c['mac']} hostname={c['hostname']} "
                      f"ap={c['ap_name']} failures={c['auth_failures']}")

    d = run_test(
        "query_unifi_ap_stats",
        lambda: query_unifi_ap_stats.invoke({}),
        required_keys=["total_aps", "online_aps", "aps"],
        skip_if_missing="UNIFI_USERNAME",
    )
    if d:
        total = d.get("total_aps", 0)
        online = d.get("online_aps", 0)
        print(f"         → {online}/{total} APs online")
        for alert in d.get("alerts", []):
            print(f"  {WARN} {alert}")

    # ── 8. Existing tools — smoke test post-refactor ──────────────────────────
    section("Smoke Tests: Pre-existing Tools (post-refactor verification)")

    from agent.tools.logs import query_security_summary
    run_test(
        "query_security_summary (ClickHouse auth via headers)",
        lambda: query_security_summary.invoke({"hours": 1}),
        docker_internal=True,
    )

    from agent.tools.proxmox_tools import query_proxmox_health
    run_test(
        "query_proxmox_health (Proxmox exporter — Docker host only)",
        lambda: query_proxmox_health.invoke({}),
        required_keys=["nodes", "vms"],
        docker_internal=True,
    )

    from agent.tools.pbs import query_pbs_backup_status
    d = run_test(
        "query_pbs_backup_status",
        lambda: query_pbs_backup_status.invoke({}),
        required_keys=["datastores"],
        skip_if_missing="PBS_TOKEN_SECRET",
    )
    if d:
        stale = d.get("stale_backups", [])
        failed = d.get("failed_tasks_48h", [])
        print(f"         → {len(stale)} stale backup groups, {len(failed)} failed tasks (48h)")

    from agent.tools.ntopng import query_ntopng_active_hosts
    run_test(
        "query_ntopng_active_hosts",
        lambda: query_ntopng_active_hosts.invoke({"ifid": 3, "perPage": 5}),
        skip_if_missing="NTOPNG_HOST",
    )

    from agent.tools.pfsense_tools import query_pfsense_firewall_rules
    run_test(
        "query_pfsense_firewall_rules (XML-RPC connectivity)",
        lambda: query_pfsense_firewall_rules.invoke({}),
        required_keys=["nat_rules"],
        skip_if_missing="PFSENSE_API_KEY",
    )

    # ── Summary ────────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    total_run = results["pass"] + results["fail"]
    print(f"Results: {results['pass']}/{total_run} passed, "
          f"{results['fail']} failed, "
          f"{results['skip']} skipped (missing config)")

    if results["skip"] > 0:
        print(f"\n{WARN} Skipped tests require env vars not set in .env:")
        skipped_vars = []
        if not os.environ.get("PFSENSE_HOST"):
            skipped_vars.append("  PFSENSE_HOST, PFSENSE_API_KEY, PFSENSE_API_SECRET — pfSense XML-RPC")
        if not os.environ.get("ADGUARD_HOST"):
            skipped_vars.append("  ADGUARD_HOST, ADGUARD_USERNAME, ADGUARD_PASSWORD — AdGuard direct API")
        if not os.environ.get("UNIFI_HOST"):
            skipped_vars.append("  UNIFI_HOST, UNIFI_USERNAME, UNIFI_PASSWORD — UniFi Controller")
        if not os.environ.get("PBS_TOKEN_SECRET"):
            skipped_vars.append("  PBS_TOKEN_SECRET — Proxmox Backup Server")
        if not os.environ.get("CROWDSEC_API_KEY"):
            skipped_vars.append("  CROWDSEC_API_KEY — CrowdSec bouncer key")
        if not os.environ.get("CLOUDFLARE_API_TOKEN"):
            skipped_vars.append("  CLOUDFLARE_API_TOKEN — Cloudflare API")
        for v in skipped_vars:
            print(v)

    print("=" * 60)

    if results["fail"] > 0:
        print(f"\n{FAIL} {results['fail']} test(s) FAILED — fix before deploying")
        sys.exit(1)
    else:
        print(f"\n{PASS} All executed tests passed")
        sys.exit(0)


if __name__ == "__main__":
    main()
