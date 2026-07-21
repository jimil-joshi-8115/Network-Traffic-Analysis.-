# Verdict — Case 05 (Nemotodes — Cracked APK Site)

## 🔴 Verdict: TRUE POSITIVE

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Ingress Tool Transfer | T1105 | Repeated download of files from a known malicious-software-adjacent domain |
| User Execution (likely, pending endpoint confirmation) | T1204 | Files downloaded from a cracked/pirated software site carry high likelihood of trojanized execution |
| Drive-by / Untrusted Software Acquisition | T1195-adjacent | Acquisition of software from an untrusted, policy-violating source |

---

## Justification

1. **The domain itself is the primary evidence** — `modandcrackedapk.com` explicitly advertises pirated/modified Android software distribution. Unlike prior cases requiring subtle technical indicators to unmask a disguised domain, this domain openly signals its risk category; no legitimate business use case exists for visiting it from a corporate workstation.
2. **Repeated, deliberate visits** — three separate DNS lookups and downloads across the session (not a single accidental click) confirm sustained, intentional engagement.
3. **Multi-megabyte downloads confirm real file acquisition** — three transfers totaling ~14MB are consistent with actual APK/installer files being downloaded, not incidental page-load traffic.
4. **Download-heavy direction correctly identifies this as a malicious-download scenario**, distinct from the exfiltration pattern seen in Case_02 — confirming the specific threat category, not just that "something suspicious happened."

Consistent with the reasoning applied to Case_005 in `SOC-Triage-Practice` (a failed brute-force attempt was still TP because the attempted action matched a known malicious pattern regardless of outcome): repeatedly downloading files from a known cracked-software distribution site is itself the risk-creating, policy-violating behavior. This verdict does not require separately confirming that the downloaded files later executed maliciously — the acquisition itself, from this specific source, is sufficient to close as TP.

---

## What Would Change This Verdict to FP

- If `modandcrackedapk.com` were confirmed as an authorized security-research or malware-analysis activity conducted by IT/security staff with a documented purpose — no such context is present here.

No such justification applies — verdict stands as TP.

---

## Recommended Response Actions

- Isolate host `DESKTOP-B8TQK49` (`10.11.26.183`) from the network
- Retrieve and analyze the downloaded files (if recoverable from disk/EDR telemetry) in a sandboxed environment to confirm malicious payload and identify the specific malware family
- Block `modandcrackedapk.com` and `193.42.38.139` at the DNS/firewall level
- Review the user's activity for policy violations regarding unauthorized software acquisition, separate from the technical malware risk
- Check for any follow-on execution or persistence established by the downloaded files (review EDR/endpoint logs if available for this host)

---

## Analysis Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Tool | Wireshark |
| Verdict | TP |
| Confidence | High |
| MITRE | T1105, T1204, T1195 (adjacent) |
