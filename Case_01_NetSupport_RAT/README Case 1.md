# Case 01 — NetSupport Manager RAT C2 Traffic

**Source:** malware-traffic-analysis.net — "2026-02-28 — Traffic analysis exercise: Easy as 123"
**PCAP:** `2026-02-28-traffic-analysis-exercise.pcap`
**Status:** 🔴 Open — Pending Analysis

---

## 🎫 Alert Summary (as given in the exercise scenario)

> As a SOC analyst, you check the SIEM and find several signature hits for **NetSupport Manager RAT** from `45.131.214.85` over TCP port 443. The activity started on 2026-02-28 at 19:55 UTC. You retrieve a packet capture (pcap) of the traffic from the internal IP address that triggered these alerts.

---

## 🎯 Task

1. Identify the internal (infected) host IP.
2. Determine how the host resolved/reached the malicious IP.
3. Analyze the HTTP traffic to confirm the nature of the connection.
4. Give a final verdict: TP / FP / Ambiguous, with full reasoning.
