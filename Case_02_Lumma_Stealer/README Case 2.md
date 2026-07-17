# Case 02 — Lumma Stealer Data Exfiltration

**Source:** malware-traffic-analysis.net — "2026-01-31 — Traffic analysis exercise: Lumma in the Room-ah!"
**PCAP:** `2026-01-31-traffic-analysis-exercise.pcap`
**Status:** 🔴 Open — Pending Analysis

---

## 🎫 Alert Summary

> Suspicious outbound activity detected from internal host `10.1.21.58`. Multiple rapid TLS connections observed to an external IP within a short window, followed by a large outbound data transfer. No further context provided — investigate the traffic capture.

---

## 🎯 Task

1. Identify the internal host and the destination(s) it contacted.
2. Determine what domain the suspicious IP resolves to (even though traffic is TLS-encrypted).
3. Analyze connection timing and data-flow direction to characterize the activity.
4. Give a final verdict: TP / FP / Ambiguous, with full reasoning.
