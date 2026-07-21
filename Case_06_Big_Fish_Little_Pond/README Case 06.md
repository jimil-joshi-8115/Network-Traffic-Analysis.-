# Case 06 — Big Fish in a Little Pond (Loader C2 / Beaconing)

**Source:** malware-traffic-analysis.net — "2024-09-04 — Traffic analysis exercise: Big Fish in a Little Pond"
**PCAP:** `2024-09-04-traffic-analysis-exercise.pcap`
**Status:** 🟢 Closed — TP

---

## 🎫 Alert Summary

> Reviewing alerts in the environment surfaced indicators that a host has been infected with malware. LAN segment: `172.17.0.0/24`, AD domain `bepositive.com`, domain controller `172.17.0.17` (`WIN-CTL9XBQ9Y19`). Investigate the pcap to determine the nature of the infection.

---

## 🎯 Task

1. Rule out normal internal AD/CDN traffic as noise.
2. Identify the external IP(s)/domain(s) involved in suspicious traffic and assess legitimacy.
3. Determine whether the host is communicating with a C2 server, and characterize the protocol/behavior.
4. Assess sustained vs. one-off engagement.
5. Give a final verdict: TP / FP / Ambiguous, with full reasoning.
