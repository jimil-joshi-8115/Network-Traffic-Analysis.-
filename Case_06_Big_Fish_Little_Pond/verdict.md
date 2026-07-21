# Verdict — Case 06 (Big Fish in a Little Pond — Loader C2)

## 🔴 Verdict: TRUE POSITIVE

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Application Layer Protocol: Web Protocols | T1071.001 | HTTP-based C2 communication disguised as ordinary web traffic |
| Ingress Tool Transfer / Exfiltration Over C2 Channel | T1105 / T1041 | Repeated encrypted POST transfers to a C2 endpoint (`/foots.php`) |
| Masquerading (spoofed User-Agent) | T1036 | Fake MSIE7/Trident User-Agent string inconsistent with host OS |
| Non-Application Layer / Raw-IP C2 | T1090-adjacent | Direct connection to a raw IP with no supporting DNS resolution |

---

## Justification

1. **Direct connection to a raw IP with no legitimate domain** — `79.124.78.197` was contacted with no preceding DNS resolution. Legitimate services are near-universally reached via domain name; a bare-IP connection is a strong standalone indicator, consistent with the same red flag seen in Case_04.
2. **Loader/stealer registration handshake confirmed** — the `GET /index.php?id=&subid=...` request and its pipe-delimited `token|subid|callback_url|` response is a recognizable C2 panel check-in pattern, not normal web traffic.
3. **Sustained, long-duration beaconing** — 49 encrypted POST requests to `/foots.php` over approximately 17.5 minutes confirms deliberate, ongoing communication rather than an accidental or single connection.
4. **Spoofed User-Agent** — the MSIE7/Trident string is internally inconsistent with the host's actual Windows NT 10.0 platform, indicating deliberate attempt to blend in with legacy/generic traffic rather than reflect the real client.
5. **Encrypted payloads with no legitimate business purpose** — binary/encrypted POST bodies to an unexplained raw-IP endpoint have no benign explanation on a corporate workstation.

Consistent with the reasoning applied in prior cases (e.g., Case_05's cracked-APK downloads, Case_04's TeamViewer RAT deployment): the combination of an untrusted/unexplained destination, a recognizable malicious protocol pattern, and sustained repeated engagement is sufficient to close as TP without requiring host-side confirmation (e.g., process execution logs) — though such confirmation would still strengthen the case if available.

---

## What Would Change This Verdict to FP

- If `79.124.78.197` were confirmed as an authorized internal tool, monitoring agent, or security-research sandbox with a documented business justification — no such context is present here.
- If the `/foots.php` and `/index.php` traffic could be attributed to a known, benign software update or telemetry mechanism — the loader-style `id`/`subid` handshake and spoofed User-Agent make this explanation implausible.

No such justification applies — verdict stands as TP.

---

## Recommended Response Actions

- Isolate host `DESKTOP-RNVO9AT` (`172.17.0.99`) from the network immediately
- Block `79.124.78.197` at the DNS/firewall/proxy level
- Extract and attempt to decrypt/decode the POST bodies to `/foots.php` (if feasible) to determine what data is being exfiltrated
- Review endpoint/EDR logs on the host for the initial execution artifact (e.g., malicious email attachment, dropped script/binary) to confirm the infection vector referenced in the exercise context
- Revisit the unresolved TLS traffic volume (62.1% of total bytes) to confirm whether it is related to this incident or unrelated legitimate encrypted traffic
- Check other hosts on `bepositive.com` for similar traffic patterns to `79.124.78.197`, in case of lateral spread

---

## Analysis Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Tool | Wireshark |
| Verdict | TP |
| Confidence | High |
| MITRE | T1071.001, T1105, T1041, T1036 |
| Open Items | TLS destination for 62.1% of byte volume not isolated this session |
