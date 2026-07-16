# Verdict — Case 01 (NetSupport Manager RAT)

## 🔴 Verdict: TRUE POSITIVE

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Remote Access Software | T1219 | Abuse of legitimate remote-support tool (NetSupport Manager) as a RAT |
| Application Layer Protocol: Web Protocols | T1071.001 | C2 communication disguised as HTTP POST traffic |
| Non-Standard Port / Protocol Mismatch | T1571-adjacent | Plaintext HTTP traffic observed on port 443, normally reserved for TLS-encrypted HTTPS |

---

## Justification

1. **The SIEM alert independently flagged this exact IP** for a known RAT signature before packet-level analysis even began — the packet capture was used to confirm, not originate, the suspicion.
2. **DNS resolution confirms deliberate contact** — the infected host (`10.2.28.88`) actively resolved `vadusa.xyz` to the malicious IP, ruling out coincidental or misconfigured traffic.
3. **The HTTP stream contains the actual C2 protocol in action** — `CMD=POLL` (check-in) and `CMD=ENCD` (encoded command/response) are NetSupport's real control-channel commands, observed directly, not inferred from indirect signals.
4. **Legitimate-tool abuse is a known, real technique** — NetSupport Manager is genuine remote-support software; attackers use tools like this specifically because their traffic blends in with legitimate IT activity. The presence of this specific software's protocol, combined with the SIEM's own detection and the unsolicited nature of the connection (no corresponding help-desk ticket/context given), confirms malicious use rather than legitimate remote support.
5. **Repeated beaconing pattern** — the POST/response cycle repeats multiple times across the capture, consistent with an active, ongoing remote-control session rather than a single ambiguous event.

This is not a technique-vs-outcome judgment call (compare Case_003/Case_011 Alert H from the SOC-Triage-Practice repo) — here, the C2 protocol itself was directly observed executing, which is decisive on its own.

---

## What Would Change This Verdict to FP

- If the connection could be tied to a documented, authorized IT help-desk remote-support session with a corresponding ticket/change record
- If `45.131.214.85` were confirmed as the organization's own legitimate NetSupport Gateway server rather than external malicious infrastructure

Neither applies here — the IP was independently flagged by the SIEM as malicious, and no legitimate support context is present.

---

## Recommended Response Actions

- Isolate host `10.2.28.88` from the network immediately
- Block `45.131.214.85` and the domain `vadusa.xyz` at the firewall/DNS level
- Investigate what commands were relayed via the encoded `DATA=` fields, if decoding is feasible, to assess what actions the attacker took on the host
- Check for NetSupport Manager client software installed on the host that was not deployed via the organization's legitimate IT asset management process
- Review other hosts for the same User-Agent/C2 pattern to determine scope

---

## Analysis Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Tool | Wireshark |
| Verdict | TP |
| Confidence | High |
| MITRE | T1219, T1071.001 |
