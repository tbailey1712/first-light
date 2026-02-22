#!/usr/bin/env python3
"""
First Light — Connection Test Script

Verifies connectivity and credentials for every configured data source
before starting the stack. Run this first and fix all failures.

Usage:
    python scripts/test_connections.py
"""

import os
import sys
import asyncio
import socket
from typing import Optional
from pathlib import Path

import httpx
from dotenv import load_dotenv

# Load .env from project root
load_dotenv(Path(__file__).parent.parent / ".env")


def env(key: str, default: str = "") -> str:
    """Get env var, stripping any trailing inline comment."""
    val = os.getenv(key, default)
    # Strip inline comments (e.g. "value  # comment" → "value")
    if val and "#" in val:
        val = val.split("#")[0]
    return val.strip()

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
SKIP = "\033[93m⚠\033[0m"
INFO = "\033[94m→\033[0m"

results: list[tuple[str, bool, str]] = []


def log_result(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    icon = PASS if ok else FAIL
    print(f"  {icon} {name}" + (f": {detail}" if detail else ""))


def log_skip(name: str, reason: str) -> None:
    results.append((name, True, f"skipped — {reason}"))
    print(f"  {SKIP} {name}: skipped — {reason}")


def section(title: str) -> None:
    print(f"\n{title}")
    print("─" * len(title))


async def test_http(
    label: str,
    url: str,
    expected_status: int = 200,
    auth: Optional[tuple[str, str]] = None,
    verify_ssl: bool = True,
    expected_text: Optional[str] = None,
    timeout: float = 5.0,
) -> bool:
    try:
        async with httpx.AsyncClient(verify=verify_ssl, timeout=timeout) as client:
            kwargs = {}
            if auth:
                kwargs["auth"] = auth
            r = await client.get(url, **kwargs)
            if r.status_code == expected_status:
                if expected_text and expected_text not in r.text:
                    log_result(label, False, f"HTTP {r.status_code} but expected text not found")
                    return False
                log_result(label, True, f"HTTP {r.status_code}")
                return True
            else:
                log_result(label, False, f"HTTP {r.status_code} (expected {expected_status})")
                return False
    except httpx.ConnectError:
        log_result(label, False, "connection refused or host unreachable")
        return False
    except httpx.TimeoutException:
        log_result(label, False, "timed out")
        return False
    except Exception as e:
        log_result(label, False, str(e))
        return False


def test_snmp(host: str, community: str, port: int = 161) -> tuple[bool, str]:
    """Test SNMP by running snmpwalk for sysDescr."""
    import subprocess
    try:
        result = subprocess.run(
            ["snmpwalk", "-v2c", "-c", community, "-t", "3", host, "SNMPv2-MIB::sysDescr.0"],
            capture_output=True, text=True, timeout=8,
        )
        if result.returncode == 0 and result.stdout.strip():
            descr = result.stdout.strip().split("=")[-1].strip().lstrip("STRING: ")
            return True, descr[:60]
        return False, result.stderr.strip() or "no response"
    except FileNotFoundError:
        # snmpwalk not installed — fall back to UDP socket test
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            resolved = socket.gethostbyname(host)
            # Minimal SNMPv2c GetRequest for sysDescr
            comm = community.encode()
            pkt = (b"\x30" + bytes([29 + len(comm)]) +
                   b"\x02\x01\x01\x04" + bytes([len(comm)]) + comm +
                   b"\xa0\x15\x02\x04\xde\xad\xbe\xef\x02\x01\x00\x02\x01\x00"
                   b"\x30\x07\x30\x05\x06\x01\x00\x05\x00")
            sock.sendto(pkt, (resolved, port))
            data, _ = sock.recvfrom(1024)
            sock.close()
            return True, "responding (install net-snmp for details)"
        except Exception as e:
            return False, str(e)
    except subprocess.TimeoutExpired:
        return False, "timed out"
    except Exception as e:
        return False, str(e)


def test_snmp_v3(host: str, username: str, port: int = 161) -> tuple[bool, str]:
    """Test SNMPv3 noAuthNoPriv with just a username."""
    import subprocess
    try:
        result = subprocess.run(
            ["snmpwalk", "-v3", "-l", "noAuthNoPriv", "-u", username,
             "-t", "3", host, "SNMPv2-MIB::sysDescr.0"],
            capture_output=True, text=True, timeout=8,
        )
        if result.returncode == 0 and result.stdout.strip():
            descr = result.stdout.strip().split("=")[-1].strip().lstrip("STRING: ")
            return True, descr[:60]
        return False, result.stderr.strip() or "no response — check username is saved in QNAP"
    except FileNotFoundError:
        return False, "snmpwalk not found — install net-snmp"
    except subprocess.TimeoutExpired:
        return False, "timed out"
    except Exception as e:
        return False, str(e)


async def run_tests() -> None:
    print("╔══════════════════════════════════════════════════╗")
    print("║         First Light — Connection Tests           ║")
    print("╚══════════════════════════════════════════════════╝")

    # ── pfSense ──────────────────────────────────────────────
    section("pfSense Plus")
    pfsense_host = env("PFSENSE_HOST")
    if pfsense_host:
        await test_http(
            "Web UI reachable",
            f"https://{pfsense_host}",
            expected_status=200,
            verify_ssl=False,
            expected_text="pfSense",
        )
        api_key = env("PFSENSE_API_KEY")
        if api_key:
            await test_http(
                "API accessible",
                f"https://{pfsense_host}/api/v1/system/info",
                verify_ssl=False,
                expected_status=200,
            )
        else:
            log_skip("API", "no API key configured (syslog only)")
    else:
        log_skip("pfSense", "PFSENSE_HOST not set")

    # ── AdGuard Home ─────────────────────────────────────────
    section("AdGuard Home")
    adguard_host = env("ADGUARD_HOST")
    adguard_user = env("ADGUARD_USERNAME")
    adguard_pass = env("ADGUARD_PASSWORD")
    proto = env("ADGUARD_PROTOCOL") or "https"
    port = env("ADGUARD_PORT") or "443"
    if adguard_host and adguard_user and adguard_pass:
        base = f"{proto}://{adguard_host}:{port}"
        # Status endpoint requires auth — 401 without creds is expected, 200 with creds is pass
        ok = await test_http(
            "Auth + status API",
            f"{base}/control/status",
            auth=(adguard_user, adguard_pass),
            verify_ssl=False,
        )
        if ok:
            await test_http(
                "Stats API",
                f"{base}/control/stats",
                auth=(adguard_user, adguard_pass),
                verify_ssl=False,
            )
            await test_http(
                "Query log enabled",
                f"{base}/control/querylog_info",
                auth=(adguard_user, adguard_pass),
                verify_ssl=False,
            )
    elif not adguard_host:
        log_skip("AdGuard", "ADGUARD_HOST not set")
    else:
        log_skip("AdGuard auth", "credentials not set")

    # ── ntopng ───────────────────────────────────────────────
    section("ntopng (Community 6.7)")
    ntopng_host = env("NTOPNG_HOST")
    ntopng_port = env("NTOPNG_PORT") or "443"
    ntopng_proto = env("NTOPNG_PROTOCOL") or "https"
    ntopng_user = env("NTOPNG_USERNAME")
    ntopng_pass = env("NTOPNG_PASSWORD")
    if ntopng_host:
        base = f"{ntopng_proto}://{ntopng_host}:{ntopng_port}"
        await test_http("Reachable (expects redirect to login)", f"{base}/", expected_status=302, verify_ssl=False)
        if ntopng_user and ntopng_pass:
            # ntopng uses cookie-based session auth — login first, then use cookie
            async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
                try:
                    login_r = await client.post(
                        f"{base}/authorize.html",
                        data={"user": ntopng_user, "password": ntopng_pass},
                    )
                    cookies = dict(login_r.cookies)
                    if not cookies:
                        login_r = await client.post(
                            f"{base}/lua/login.lua",
                            data={"user": ntopng_user, "password": ntopng_pass},
                        )
                        cookies = dict(login_r.cookies)

                    if cookies:
                        log_result("Session login", True, "got session cookie")
                        # Try multiple known Prometheus endpoint paths
                        prom_paths = ["/lua/metrics.lua", "/metrics", "/lua/pro/rest/v2/get/ntopng/metrics.lua"]
                        prom_ok = False
                        for path in prom_paths:
                            r = await client.get(f"{base}{path}", cookies=cookies)
                            if r.status_code == 200 and ("TYPE" in r.text or "HELP" in r.text):
                                log_result("Prometheus metrics", True, f"found at {path}")
                                prom_ok = True
                                break
                        if not prom_ok:
                            # CE requires --prometheus-exporter-port CLI flag, not a UI toggle
                            log_skip("Prometheus metrics",
                                "CE needs --prometheus-exporter-port=9000 in /etc/ntopng/ntopng.conf")
                        r2 = await client.get(
                            f"{base}/lua/rest/v2/get/ntopng/interfaces.lua",
                            cookies=cookies,
                        )
                        log_result("Interfaces API", r2.status_code == 200, f"HTTP {r2.status_code}")
                    else:
                        log_result("Session login", False, "no session cookie — check credentials")
                except Exception as e:
                    log_result("ntopng login", False, str(e))
        else:
            log_skip("ntopng auth", "credentials not set")
    else:
        log_skip("ntopng", "NTOPNG_HOST not set")

    # ── Network Switch SNMP ───────────────────────────────────
    section("Switch (TL-SG2424 SNMP)")
    switch_host = env("SWITCH_HOST")
    snmp_community = env("SNMP_COMMUNITY")
    if switch_host and snmp_community:
        print(f"  {INFO} Testing SNMP to {switch_host} ...")
        ok, detail = test_snmp(switch_host, snmp_community)
        log_result("SNMP reachable", ok, detail)
        if not ok:
            print(f"       Hint: verify SNMP is enabled on the switch Global Config tab")
    elif not switch_host:
        log_skip("Switch SNMP", "SWITCH_HOST not set")
    else:
        log_skip("Switch SNMP", "SNMP_COMMUNITY not set")

    # ── UniFi Controller ─────────────────────────────────────
    section("UniFi Controller")
    unifi_host = env("UNIFI_HOST")
    unifi_port = env("UNIFI_PORT") or "8443"
    unifi_user = env("UNIFI_USERNAME")
    unifi_pass = env("UNIFI_PASSWORD")
    unifi_site = env("UNIFI_SITE") or "default"
    if unifi_host and unifi_user and unifi_pass:
        base = f"https://{unifi_host}:{unifi_port}"
        # UniFi modern API (Network Application)
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            try:
                r = await client.post(
                    f"{base}/api/login",
                    json={"username": unifi_user, "password": unifi_pass},
                )
                if r.status_code == 200 and "unifises" in r.cookies:
                    log_result("Login", True, "authenticated successfully")
                    # Test sites endpoint
                    r2 = await client.get(f"{base}/api/self/sites", cookies=r.cookies)
                    log_result("Sites API", r2.status_code == 200, f"HTTP {r2.status_code}")
                elif r.status_code == 400:
                    log_result("Login", False, "bad credentials")
                else:
                    log_result("Login", False, f"HTTP {r.status_code}")
            except httpx.ConnectError:
                log_result("Controller reachable", False, "connection refused")
            except Exception as e:
                log_result("Login", False, str(e))
    elif not unifi_host:
        log_skip("UniFi", "UNIFI_HOST not set")
    else:
        log_skip("UniFi auth", "credentials not set")

    # ── Proxmox VE ───────────────────────────────────────────
    section("Proxmox VE")
    pve_host = env("PROXMOX_HOST")
    pve_port = env("PROXMOX_PORT") or "8006"
    pve_token_id = env("PROXMOX_TOKEN_ID")
    pve_token_secret = env("PROXMOX_TOKEN_SECRET")
    # Fall back to username/password if no token
    pve_user = env("PROXMOX_USERNAME")
    pve_pass = env("PROXMOX_PASSWORD")
    pve_realm = env("PROXMOX_REALM") or "pam"
    if pve_host:
        base = f"https://{pve_host}:{pve_port}/api2/json"
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            try:
                if pve_token_id and pve_token_secret:
                    # API token auth: Authorization: PVEAPIToken=USER@REALM!TOKENID=SECRET
                    auth_header = f"PVEAPIToken={pve_token_id}={pve_token_secret}"
                    r = await client.get(
                        f"{base}/nodes",
                        headers={"Authorization": auth_header},
                    )
                    if r.status_code == 200:
                        nodes = [n["node"] for n in r.json()["data"]]
                        log_result("API token auth", True, f"nodes: {', '.join(nodes)}")
                        # Also check version
                        r2 = await client.get(
                            f"{base}/version",
                            headers={"Authorization": auth_header},
                        )
                        if r2.status_code == 200:
                            ver = r2.json()["data"].get("version", "unknown")
                            log_result("Version", True, f"PVE {ver}")
                    else:
                        log_result("API token auth", False, f"HTTP {r.status_code} — check token ID/secret")
                elif pve_user and pve_pass:
                    r = await client.post(
                        f"{base}/access/ticket",
                        data={"username": f"{pve_user}@{pve_realm}", "password": pve_pass},
                    )
                    if r.status_code == 200:
                        ticket = r.json()["data"]["ticket"]
                        token = r.json()["data"]["CSRFPreventionToken"]
                        log_result("Password auth", True, f"authenticated as {pve_user}@{pve_realm}")
                        r2 = await client.get(
                            f"{base}/nodes",
                            cookies={"PVEAuthCookie": ticket},
                            headers={"CSRFPreventionToken": token},
                        )
                        if r2.status_code == 200:
                            nodes = [n["node"] for n in r2.json()["data"]]
                            log_result("Nodes API", True, f"nodes: {', '.join(nodes)}")
                    else:
                        log_result("Password auth", False, f"HTTP {r.status_code}")
                else:
                    log_skip("Proxmox auth", "no token or credentials set")
            except httpx.ConnectError:
                log_result("Proxmox reachable", False, "connection refused")
            except Exception as e:
                log_result("Proxmox auth", False, str(e))
    else:
        log_skip("Proxmox", "PROXMOX_HOST not set")

    # ── QNAP SNMP ────────────────────────────────────────────
    section("QNAP NAS (SNMP)")
    qnap_host = env("QNAP_HOST")
    qnap_version = env("QNAP_SNMP_VERSION") or "2c"
    qnap_username = env("QNAP_SNMP_USERNAME")
    qnap_community = env("QNAP_SNMP_COMMUNITY")
    if qnap_host and (qnap_username or qnap_community):
        print(f"  {INFO} Testing SNMPv{qnap_version} to {qnap_host} ...")
        if qnap_version == "3" and qnap_username:
            ok, detail = test_snmp_v3(qnap_host, qnap_username)
        else:
            ok, detail = test_snmp(qnap_host, qnap_community)
        log_result("SNMP reachable", ok, detail)
        if not ok and qnap_version == "3":
            print(f"       Hint: set username 'firstlight' in QNAP Control Panel → Network Services → SNMP")
    elif not qnap_host:
        log_skip("QNAP SNMP", "QNAP_HOST not set")
    else:
        log_skip("QNAP SNMP", "QNAP_SNMP_USERNAME not set — add username in QNAP SNMP settings first")

    # ── Ethereum Validator ───────────────────────────────────
    section("Ethereum Validator")
    val_host = env("VALIDATOR_HOST")
    if val_host:
        nimbus_ok = await test_http(
            "Nimbus metrics (8008)",
            f"http://{val_host}:8008/metrics",
        )
        if not nimbus_ok:
            print(f"       Hint: Nimbus may be bound to 127.0.0.1 only.")
            print(f"       Add --metrics-address=0.0.0.0 to your Nimbus service and restart.")
        beacon_ok = await test_http(
            "Nimbus beacon API (5052)",
            f"http://{val_host}:5052/eth/v1/node/version",
        )
        if not beacon_ok:
            print(f"       Hint: Add --rest-address=0.0.0.0 to your Nimbus service and restart.")
        await test_http(
            "Nethermind metrics (6060)",
            f"http://{val_host}:6060/metrics",
        )
    else:
        log_skip("Validator", "VALIDATOR_HOST not set")

    # ── Uptime Kuma ──────────────────────────────────────────
    section("Uptime Kuma")
    uk_host = env("UPTIME_KUMA_HOST")
    uk_proto = env("UPTIME_KUMA_PROTOCOL") or "https"
    uk_port = env("UPTIME_KUMA_PORT") or "443"
    if uk_host:
        # Follow redirects (Uptime Kuma returns 302 → final page)
        try:
            async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as client:
                r = await client.get(f"{uk_proto}://{uk_host}:{uk_port}")
                log_result("Reachable", r.status_code == 200, f"HTTP {r.status_code}")
        except Exception as e:
            log_result("Reachable", False, str(e))
        uk_key = env("UPTIME_KUMA_API_KEY")
        if uk_key:
            await test_http(
                "Metrics endpoint",
                f"{uk_proto}://{uk_host}:{uk_port}/metrics",
                verify_ssl=False,
            )
        else:
            log_skip("Uptime Kuma API key", "UPTIME_KUMA_API_KEY not set")
    else:
        log_skip("Uptime Kuma", "UPTIME_KUMA_HOST not set")

    # ── Anthropic API ────────────────────────────────────────
    section("Anthropic API (AI Agent)")
    anthropic_key = env("ANTHROPIC_API_KEY")
    if anthropic_key:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    "https://api.anthropic.com/v1/models",
                    headers={
                        "x-api-key": anthropic_key,
                        "anthropic-version": "2023-06-01",
                    },
                )
                log_result("API key valid", r.status_code == 200, f"HTTP {r.status_code}")
        except Exception as e:
            log_result("API reachable", False, str(e))
    else:
        log_skip("Anthropic", "ANTHROPIC_API_KEY not set")

    # ── Summary ──────────────────────────────────────────────
    print("\n" + "═" * 52)
    print("  SUMMARY")
    print("═" * 52)
    passed = sum(1 for _, ok, detail in results if ok and "skipped" not in detail)
    failed = sum(1 for _, ok, _ in results if not ok)
    skipped = sum(1 for _, ok, detail in results if ok and "skipped" in detail)

    print(f"  {PASS} Passed:  {passed}")
    if failed:
        print(f"  {FAIL} Failed:  {failed}")
    if skipped:
        print(f"  {SKIP} Skipped: {skipped}")
    print()

    if failed:
        print("  Failed checks:")
        for name, ok, detail in results:
            if not ok:
                print(f"    {FAIL} {name}: {detail}")
        print()
        print("  Fix failures above before running docker compose up.")
        sys.exit(1)
    else:
        print("  All checks passed. Ready for Phase 2 (docker compose up).")


if __name__ == "__main__":
    asyncio.run(run_tests())
