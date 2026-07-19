# Case 04 — Fake Software Download Site → TeamViewer RAT Deployment

**Source:** malware-traffic-analysis.net — "2025-01-22 — Traffic analysis exercise: Download from fake software site"
**PCAP:** `2025-01-22-traffic-analysis-exercise.pcap`
**Status:** 🔴 Open — Pending Analysis

---

## 🎫 Alert Summary

> A user on host `DESKTOP-L8C5GSJ.bluemoontuesday.com` (`10.1.17.215`) downloaded a file believed to be legitimate software. Repeated outbound HTTP activity to an external IP was subsequently observed, along with DNS lookups for a well-known remote-access software vendor. No further context provided — investigate the traffic capture.

---

## 🎯 Task

1. Identify the internal host and the external IP(s) it contacted.
2. Determine what was downloaded and how it was delivered (script, obfuscation technique).
3. Identify any beaconing/check-in pattern.
4. Determine what final payload was deployed and its purpose.
5. Give a final verdict: TP / FP / Ambiguous, with full reasoning.
