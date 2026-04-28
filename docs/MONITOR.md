# Active Monitoring Items

Items listed here require explicit attention in daily reports.
Agents should check and report on these when status CHANGES.
Domain tags in [brackets] control which agents see each item.

---

## Watch Items

- **Flume leak detector** [home_automation]: Known firmware bug causing persistent false leak_detected/high_flow alerts. Report only if the alert CLEARS (meaning the bug may be fixed) or if a REAL leak correlates with other sensors (e.g. humidity spike, sump pump activity beyond normal).
- **Switch port 5 surveillance gaps** [infrastructure]: Chronic link flaps (68+/day) on backyard camera EoC path causing recording gaps on 192.168.3.15. Report only if flap rate changes significantly (>2x or drops to 0 indicating permanent failure or fix).
- **DNS query volume trend** [dns_security]: Volume has been elevated (~80-90K vs ~60K historical baseline). Report only if it exceeds 120K or drops below 40K — both would indicate a real change worth investigating.
