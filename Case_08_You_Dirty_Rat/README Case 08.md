# Case 08 — You Dirty Rat! (RAT Infection — IP Geolocation Fingerprinting)

**Source:** malware-traffic-analysis.net — "2024-07-30 — Traffic analysis exercise: You dirty rat!"
**PCAP:** `2024-07-30-traffic-analysis-exercise.pcap`
**Status:** 🟢 Closed — TP

---

## 🎫 Alert Summary

> Reviewing alerts in the environment surfaced indicators of a possible RAT (Remote Access Trojan) infection on a workstation within the `wiresharkworkshop.online` AD domain. Investigate the pcap to determine the nature of the infection.

---

## 🎯 Task

1. Rule out normal internal AD/CDN/OS telemetry traffic as noise.
2. Identify any external hosts or services involved in suspicious activity.
3. Determine whether the host performed reconnaissance/fingerprinting behavior consistent with a RAT.
4. Attempt to isolate the actual command-and-control (C2) channel.
5. Give a final verdict: TP / FP / Ambiguous, with full reasoning.
