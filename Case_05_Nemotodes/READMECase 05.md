# Case 05 — Nemotodes (Cracked APK Site Malicious Downloads)

**Source:** malware-traffic-analysis.net — "2024-11-26 — Traffic analysis exercise: Nemotodes"
**PCAP:** `2024-11-26-traffic-analysis-exercise.pcap`
**Status:** 🔴 Open — Pending Analysis

---

## 🎫 Alert Summary

> Repeated large outbound TLS connections observed from host `DESKTOP-B8TQK49.local` (`10.11.26.183`) to an external IP, alongside DNS lookups for a domain associated with pirated/modified software distribution. No further context provided — investigate the traffic capture.

---

## 🎯 Task

1. Identify the internal host and rule out normal internal Active Directory/Microsoft CDN traffic as noise.
2. Identify the destination domain(s) involved and assess their legitimacy.
3. Determine the direction of data flow (upload vs. download) to characterize the activity.
4. Assess whether repeated visits confirm deliberate, sustained engagement rather than a one-off accident.
5. Give a final verdict: TP / FP / Ambiguous, with full reasoning.
