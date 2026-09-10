# Priority Alerts

Items listed here trigger an **immediate push notification** (Pushover high-priority)
when detected in the daily report. These are findings that require same-day attention.

Each alert has:
- A **keyword pattern** (case-insensitive substring match against the final report text)
- A **title** for the push notification
- A **priority**: `high` (sound + vibration) or `emergency` (repeats until acknowledged)

---

## Active Alerts

- **Backup failure**
  - keywords: `backup failed`, `backup job failed`, `backup did not complete`, `offsite backup failure`, `no offsite backup`, `b2 backup failed`, `pbs task error`, `backup job error`
  - title: Backup Failure
  - priority: high

- **Unregistered device on isolated VLAN**
  - keywords: `unregistered device`, `unknown device on vlan 3`, `unknown device on vlan 4`, `not in dhcp_leases`, `unrecognized mac on vlan 3`, `new device on cctv vlan`
  - title: Unregistered Device on Isolated VLAN
  - priority: high

- **MAC randomization on VLAN 1**
  - keywords: `randomized mac`, `locally administered mac`, `private wifi address`, `mac randomization`
  - title: VLAN 1 MAC Randomization Detected
  - priority: high

- **CCTV VLAN outbound allowed**
  - keywords: `cctv outbound allowed`, `cctv egress allowed`, `vlan 3 outbound allowed`, `camera reached external`
  - title: CCTV VLAN Outbound Traffic ALLOWED
  - priority: emergency

- **Validator offline**
  - keywords: `validator offline`, `beacon chain unreachable`, `attestation missed`
  - title: ETH Validator Issue
  - priority: high

- **Cross-VLAN breach**
  - keywords: `cross-vlan breach`, `vlan breach`, `unauthorized cross-vlan`
  - title: Cross-VLAN Breach Detected
  - priority: emergency
