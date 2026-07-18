# Case 03 — "It's a Trap!" (Masquerading Domain + Abused Cloudflare Tunnel Exfiltration)

**Source:** malware-traffic-analysis.net — "2025-06-13 — Traffic analysis exercise: It's a trap!"
**PCAP:** `2025-06-13-traffic-analysis-exercise.pcap`
**Status:** 🔴 Open — Pending Analysis

---

## 🎫 Alert Summary

> Repeated outbound POST traffic observed from host `DESKTOP-5AVE44C.massfriction.com` (`10.6.13.133`) to two external destinations, both carrying unusual, non-standard content. No further context provided — investigate the traffic capture.

---

## 🎯 Task

1. Identify the internal host and rule out normal internal Active Directory/domain traffic as noise.
2. Identify the destination domains involved and assess their legitimacy.
3. Analyze the HTTP request pattern (content type, URL structure, payload) for both destinations.
4. Give a final verdict: TP / FP / Ambiguous, with full reasoning.
