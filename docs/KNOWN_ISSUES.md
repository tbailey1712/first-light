# Known Issues & Suppressions

Items listed here are automatically injected into domain agent prompts.
Do NOT flag these as findings unless the stated condition changes.
Domain tags in [brackets] control which agents see each item.

---

## Suppressions

- **Apple TV UDP 3722** [firewall_threat]: 192.168.2.12 (atv-basement) sends tens of thousands of UDP 3722 (AirPlay/HomeKit discovery) cross-VLAN to VLAN 1 hosts daily. Firewall blocks all of it (VLAN2→VLAN1 deny). High volume is inherent to the protocol. Do NOT flag regardless of block count or targets.
- **AT&T gateway SSDP** [firewall_threat]: 192.168.0.239 on the WAN-side segment (gateway at 192.168.11.11) sends thousands of SSDP broadcasts (UDP/1900) to 239.255.255.250 daily on mvneta0. Normal WAN-side noise. The 192.168.0.x subnet is upstream of pfSense, NOT an undefined VLAN.
- **Nest Hub broadcast** [firewall_threat]: 192.168.2.47 (HubMax-Kitchen) broadcasts UDP 9478/9999 (Google Cast/Home discovery) to 255.255.255.255. Firewall blocks at VLAN boundary. Normal smart-home behavior.
- **Broadcast/multicast discovery** [firewall_threat]: IoT devices on VLAN 2 routinely send broadcast (255.255.255.255) and multicast (239.255.255.250:1900 SSDP/UPnP) discovery traffic. Firewall blocks at VLAN boundary. Normal. Do NOT flag.
- **tbailey SSH from VLAN 2** [firewall_threat]: SSH from tbailey on VLAN 2 to Docker host (192.168.2.106) is NORMAL — the owner works from devices on the IoT VLAN (e.g. MacBook on IoT WiFi). Only flag SSH from VLAN 2 if the username is unexpected.
- **Work MacBook 192.168.1.100** [firewall_threat, dns_security]: Digitas-Macbook-Dock (USB dock). Runs enterprise endpoint security (Zscaler, CrowdStrike). DoH attempts, persistent inbound connections from cloud security vendor IPs, high-frequency mDNS, and unusual query patterns are all normal enterprise endpoint behavior.
- **Blocked external scans** [firewall_threat]: External port scans/sweeps where ALL traffic was blocked are not findings. The firewall doing its job is not actionable. Only flag if: (a) traffic was ALLOWED through, (b) volume >50K from single IP, or (c) IP also appears in auth events.
- **CCTV outbound blocks** [firewall_threat]: 192.168.3.x (CCTV VLAN) attempting outbound connections (UDP/10001, cloud relay, P2P) is expected. Cameras try to phone home and the firewall blocks them. Only flag if traffic is ALLOWED out.
- **Subdomain enumeration** [firewall_threat, dns_security]: Random-string, hex-string, and SRV probes against mcducklabs.com (e.g. _8123._https.ha, random GUIDs) are automated DNS recon returning NXDOMAIN. Not actionable unless a probe hits a live record (verify with check_public_dns).
- **WAF hits on non-resolving subdomains** [firewall_threat]: Low-volume WAF hits on subdomains that don't resolve publicly (tracker, nas, qnap, unifi, zoneminder, webmail, etc.) are not findings. If it doesn't resolve, there's nothing to protect.
- **Switch port 5 link flaps** [infrastructure, network_flow]: Backyard camera EoC path. Chronic physical-layer failure (68+ flaps/day). Known long-term issue on the maintenance backlog. Do NOT flag or recommend inspection.
- **CT 107 (encoder) dormant** [infrastructure]: Intentionally stopped. Do not flag as orphaned or recommend pruning.
- **Docker VM memory ~97%** [infrastructure]: Known constraint at 8.6 GB. Report the value but do NOT make it a finding or recommend increasing allocation.
- **Flume leak false positive** [home_automation]: Flume water monitor leak_detected and high_flow sensors stuck ON due to known HA integration bug. Ignore all Flume leak/flow alerts until this entry is removed.
- **pulse.mcducklabs.com queries** [dns_security]: Stale reference from decommissioned Proxmox monitor. The malformed pulse.mcducklabs.com.mcducklabs.com variant is Docker search domain config. Not a security issue.
- **iPhone backend-capital.com** [dns_security]: 192.168.1.58 (iPhone15Pro) → backend-capital.com blocks are a cryptocurrency price tracking app blocked by ad filter. Normal.
- **Apple device TXT ratios** [dns_security]: Apple devices (iPhones, iPads, Apple TV) routinely hit TXT query ratios of 0.5–1.2 due to iCloud Private Relay endpoint discovery, APNs TXT lookups, and service discovery. This is normal iOS behavior, not DNS tunneling. Only flag TXT ratio above 2.0 on Apple devices, or above 3.0 on any device. Multiple Apple devices spiking together confirms platform behavior, not a shared VPN.
- **DNS volume deviations** [dns_security]: Deviations under 50% from baseline are not findings. Note in baseline section only. Only flag if sustained 3+ days or a specific cause is identified.
- **Nominal subsystem status** [infrastructure]: Do NOT report "all healthy" status for Frigate, Proxmox, QNAP, etc. Only report anomalies. If everything is nominal, omit the section entirely.
- **Routine WiFi/latency metrics** [infrastructure, wireless, network_flow]: WiFi signal strength, network latency, and routine performance metrics belong in the weekly report. Only include in daily if there's a notable degradation (>20% change from baseline).

## Cloudflare Access Services

- **CF Access protected services** [firewall_threat, dns_security, cloudflare]: langfuse.mcducklabs.com and ai.mcducklabs.com are behind CF Access + WAF. WAF hits being blocked = protection working. Do NOT flag as unprotected or recommend adding CF Access.

## Rules

- **IP resolution** [firewall_threat, dns_security, network_flow, infrastructure]: Before flagging any internal IP (192.168.x.x) as unknown, check docs/dhcp_leases.md. If the IP is in the lease table, use the device name and do not recommend identification.
- **Public DNS verification** [firewall_threat, dns_security, cloudflare]: Before claiming any *.mcducklabs.com subdomain is "resolving externally" or "exposed," call check_public_dns() to verify via Google 8.8.8.8. Internal DNS queries do NOT mean external exposure.
