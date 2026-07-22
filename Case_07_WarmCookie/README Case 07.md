# Case 07 — WarmCookie (Fake FedEx Invoice → Malicious JS Loader)

**Source:** malware-traffic-analysis.net — "2024-08-15 — Traffic analysis exercise: WarmCookie"
**PCAP:** `2024-08-15-traffic-analysis-exercise.pcap`
**Status:** 🟢 Closed — TP

---

## 🎫 Alert Summary

> Reviewing alerts in the environment surfaced indicators that a host has been infected with malware, involving a suspicious download from a domain impersonating a known courier brand. Investigate the pcap to determine the nature of the infection.

---

## 🎯 Task

1. Rule out normal internal AD/CDN/browser telemetry traffic as noise.
2. Identify the phishing domain(s) and destination IP(s), and assess legitimacy.
3. Determine what was downloaded and how it was disguised.
4. Trace the payload delivery mechanism end-to-end.
5. Give a final verdict: TP / FP / Ambiguous, with full reasoning.
