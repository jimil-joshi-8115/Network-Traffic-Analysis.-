# Verdict — Case 02 (Lumma Stealer)

## 🔴 Verdict: TRUE POSITIVE

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Archive Collected Data / Data from Local System | T1560, T1005 | Local browser/system data (passwords, cookies, autofill, wallet data) collected for exfiltration |
| Exfiltration Over C2 Channel | T1041 | Stolen data transmitted over the same TLS channel used for check-in |
| Application Layer Protocol: Web Protocols | T1071.001 | C2/exfiltration disguised as standard HTTPS traffic |

---

## Justification

1. **Anomalous conversation pattern** — 13 short-lived TLS connections plus one large (~2MB) transfer, all to a single external IP, is structurally inconsistent with normal browsing traffic observed elsewhere in the same capture.
2. **SNI reveals a suspicious destination** — `whitepepper.su` has no legitimate business purpose; the `.su` TLD combined with an unrelated, non-descriptive name matches known malicious-infrastructure patterns.
3. **Burst timing matches known infostealer behavior** — 13 fresh connections within ~30 seconds reflects rapid, sequential data collection and transmission, distinct from the steady beaconing pattern of RAT-style malware (see Case_01).
4. **Packet-direction imbalance confirms exfiltration** — 1,035 client packets vs. 6 server packets in the largest stream is decisive: the infected host is overwhelmingly sending data outward, which is the technical fingerprint of data upload/exfiltration rather than normal content retrieval.

No single indicator here would be fully conclusive alone (an unusual domain, a burst of connections, or an imbalanced transfer could each theoretically have an innocent explanation in isolation) — but combined, with no corroborating legitimate business context, they present a decisive, cohesive picture consistent with known Lumma Stealer exfiltration behavior.

---

## What Would Change This Verdict to FP

- If `whitepepper.su` were confirmed as an internal or authorized third-party service (e.g. a legitimate but obscure business tool) — no such justification is evident here
- If the large outbound transfer were confirmed as an authorized backup/sync process rather than unexplained stolen-data upload

Neither applies — verdict stands as TP.

---

## Recommended Response Actions

- Isolate host `10.1.21.58` from the network immediately
- Block `153.92.1.49` and the domain `whitepepper.su` at the firewall/DNS level
- Assume all browser-stored credentials, cookies, and autofill data on the affected host are compromised — force password resets for any accounts that had saved credentials on this machine
- Check for cryptocurrency wallet files on the host, as Lumma Stealer is known to target these specifically
- Review other hosts for the same SNI/connection-burst pattern to determine scope

---

## Analysis Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Tool | Wireshark |
| Verdict | TP |
| Confidence | High |
| MITRE | T1560, T1005, T1041, T1071.001 |
