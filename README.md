# 🕸️ Network-Traffic-Analysis

Packet-level threat analysis using **Wireshark** on real, public malware traffic captures sourced from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/). Unlike the log-based triage work in [SOC-Triage-Practice](https://github.com/jimil-joshi-8115/SOC-Triage-Practice), this repo verifies attacker activity at the actual network-packet level — DNS resolutions, HTTP/TCP streams, and C2 protocol traffic — rather than pre-summarized SIEM alerts.

Same TP/FP/Ambiguous discipline as the rest of the SOC portfolio applies here: every case ends in a documented verdict with full reasoning, not just a description of what was observed in the packets.

---

## 📂 Repo Structure

```
Network-Traffic-Analysis/
└── Case_01_NetSupport_RAT/
    ├── README.md          → the ticket / exercise scenario
    ├── investigation.md   → step-by-step Wireshark analysis
    ├── verdict.md          → final TP/FP/Ambiguous call, MITRE mapping, reasoning
    └── screenshots/
```

---

## 📋 Case Index

| Case | Source Exercise | Verdict | MITRE |
|---|---|---|---|
| [Case_01](Case_01_NetSupport_RAT/) | 2026-02-28 — "Easy as 123" (malware-traffic-analysis.net) | 🔴 TP | T1219, T1071.001 |
| [Case_02](Case_02_Lumma_Stealer/) | 2026-01-31 — "Lumma in the Room-ah!" (malware-traffic-analysis.net) | 🔴 TP | T1560, T1005, T1041, T1071.001 |

---

## 🔗 Companion Repos

- [SOC-Triage-Practice](https://github.com/jimil-joshi-8115/SOC-Triage-Practice) — 20-case log-based triage practice
- [SOC-Lab-Splunk](https://github.com/jimil-joshi-8115/SOC-Lab-Splunk) — foundational detection labs and dashboards
- [SOC-IR-Playbooks](https://github.com/jimil-joshi-8115/SOC-IR-Playbooks) — full incident response runbooks
- [Rakshak-SOC](https://github.com/jimil-joshi-8115/Rakshak-SOC) — custom-built SIEM dashboard
- [Rakshak-EMAIL](https://github.com/jimil-joshi-8115/Rakshak-_EMAIL) — AI-powered phishing analysis platform

---

## 👤 Analyst

**Jimil Joshi** — SOC L1 Analyst (Fresher)
TryHackMe SOC L1 · Deloitte Cyber Job Simulation · TATA Cybersecurity Analyst Simulation (IAM) · Ministry of Home Affairs "Cyber Smart"
[LinkedIn](https://linkedin.com/in/jimil-joshi-soc-analyst) · [GitHub](https://github.com/jimil-joshi-8115)
