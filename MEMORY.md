# First Light Project Memory

This file captures authoritative facts that override anything stated elsewhere (including CLAUDE.md).

---

## VLAN Topology (authoritative)

Confirmed by user 2026-03-18. CLAUDE.md has this WRONG — do not use CLAUDE.md VLAN assignments.

| VLAN | Name | Trust | WAN | Cross-VLAN | IP Range |
|------|------|-------|-----|------------|----------|
| 1 | Trusted LAN ("public") | High | Yes | Yes | 192.168.1.x |
| 2 | IoT Devices | Low | Yes | No (cannot see VLAN 1) | 192.168.2.x |
| 3 | CCTV | None | No | No (fully isolated) | 192.168.3.x |
| 4 | DMZ (Ethereum validator) | Low | Yes (WAN only) | No | 192.168.4.x |
| 10 | WiFi Guest | None | Yes | No | 192.168.10.x |

**There is no VLAN 5.** CLAUDE.md incorrectly refers to a VLAN 5 for IoT — ignore this.

### Implications for security logic

- 192.168.2.x devices are IoT, not trusted user devices. High DNS block rates on 192.168.2.x are expected/less alarming than on 192.168.1.x.
- Any WAN or cross-VLAN traffic from 192.168.3.x (CCTV) is a security violation.
- 192.168.4.x (DMZ/Validator) should only have WAN traffic — any cross-VLAN traffic is a violation.
- hubmax-kitchen and similar devices on 192.168.2.x are IoT, not trusted clients.

---

## IP Resolution Requirement

All agent outputs must resolve IPs to hostnames before presenting findings to the user.

**Why:** IPs alone are not useful for identifying devices. The user explicitly requires hostname resolution.

**How to apply:**
- Add reverse DNS / hostname lookup to every tool or agent node that surfaces IP addresses.
- Resolution priority: ntopng host data (has hostnames) → topology.yaml known devices → reverse DNS lookup.
- Implement a shared `resolve_hostname(ip: str) -> str` utility in `agent/tools/` that follows this priority order.
- Never surface a raw IP in a Telegram message or digest report without attempting resolution first.
