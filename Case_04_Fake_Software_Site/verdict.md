# Verdict — Case 04 (Fake Software Site → TeamViewer RAT)

## 🔴 Verdict: TRUE POSITIVE

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Obfuscated Files or Information | T1027 | String-obfuscation of `FromBase64String` method name to evade detection |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Fileless execution via `iex` (Invoke-Expression) of decoded content |
| Ingress Tool Transfer | T1105 | Download of script and subsequent payload from external server |
| Application Layer Protocol: Web Protocols | T1071.001 | Beaconing/check-in disguised as repeated standard HTTP GET requests |
| Remote Access Software | T1219 | Silent deployment of legitimate TeamViewer software for persistent remote access |

---

## Justification

1. **No DNS resolution before connection** — the host connected directly to a raw IP (`5.252.153.241`), consistent with malicious infrastructure avoiding domain registration/reputation tracking.
2. **Fileless, obfuscated PowerShell execution** — the downloaded `.ps1` script uses `iex` to run Base64-decoded content directly in memory, with the decoding method name itself deliberately scrambled to defeat simple string-based detection. This combination of fileless execution plus targeted obfuscation has no legitimate everyday justification.
3. **Confirmed beaconing pattern** — 13+ repeated GET requests at consistent ~5 second intervals, each returning 404 until a final 200 OK, is a clear automated check-in pattern, not human browsing behavior.
4. **Legitimate software weaponized without consent** — the final payload deploys real TeamViewer components, confirmed via DNS lookups to genuine TeamViewer infrastructure (`ping3.dyngate.com`, `tv-ns1.teamviewer.com`). While TeamViewer itself is legitimate software, its installation here was triggered by an obfuscated, beaconing malware chain with no user-initiated installation process — this is remote-access backdoor deployment, not legitimate software use, applying the same reasoning as Case_01's NetSupport Manager abuse.

No single stage in isolation would be fully conclusive on its own, but the complete chain — raw-IP connection, obfuscated fileless execution, automated beaconing, and silent legitimate-tool weaponization — leaves no reasonable innocent explanation.

---

## What Would Change This Verdict to FP

- If the PowerShell script and subsequent TeamViewer deployment were confirmed as part of an authorized IT remote-support deployment tool with a documented internal process (highly inconsistent with the observed obfuscation and raw-IP delivery, but theoretically the only scenario that would change this verdict)

No such justification is present — verdict stands as TP.

---

## Recommended Response Actions

- Isolate host `DESKTOP-L8C5GSJ` (`10.1.17.215`) from the network immediately
- Uninstall the silently-deployed TeamViewer instance and reset any credentials that may have been exposed via unauthorized remote access
- Block `5.252.153.241` and `45.125.66.32` at the firewall/DNS level
- Retrieve and analyze the full decoded PowerShell payload (Base64 content) to determine additional capabilities or persistence mechanisms established
- Review other hosts for the same fake-download-site → obfuscated-PowerShell → TeamViewer pattern to determine scope

---

## Analysis Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Tool | Wireshark |
| Verdict | TP |
| Confidence | High |
| MITRE | T1027, T1059.001, T1105, T1071.001, T1219 |
