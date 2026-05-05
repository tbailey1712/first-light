# Priority Alerts

Items listed here trigger an **immediate push notification** (Pushover high-priority)
when detected in the daily report. These are findings that require same-day attention.

Each alert has:
- A **keyword pattern** (case-insensitive substring match against the final report text)
- A **title** for the push notification
- A **priority**: `high` (sound + vibration) or `emergency` (repeats until acknowledged)

---

## Active Alerts

- **MAC randomization on VLAN 1**
  - keywords: `randomized mac`, `locally administered mac`, `private wifi address`, `mac randomization`
  - title: VLAN 1 MAC Randomization Detected
  - priority: high

- **CCTV VLAN outbound allowed**
  - keywords: `cctv`, `vlan 3`, `allowed out`, `egress allowed`
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
