# Verdict — Case 03 ("It's a Trap!")

## 🔴 Verdict: TRUE POSITIVE

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Exfiltration Over C2 Channel | T1041 | Repeated large-volume POST uploads of encoded/binary data |
| Application Layer Protocol: Web Protocols | T1071.001 | Malicious traffic disguised as standard HTTP POST requests |
| Proxy: Multi-hop Proxy / Domain Fronting-adjacent | T1090 | Abuse of Cloudflare's legitimate Quick Tunnel infrastructure to obscure true destination and evade network-level blocking |
| Masquerading | T1036.005 | Domain name (`windows-msgas.com`) deliberately crafted to resemble legitimate Microsoft/Windows infrastructure |

---

## Justification

1. **Internal noise was correctly ruled out first** — SMB/Kerberos/LDAP/RPC traffic between internal hosts and Microsoft Delivery Optimization domains were identified as normal Windows/AD background activity, not investigated further, keeping focus on the genuinely anomalous traffic.
2. **Two independent destinations, identical suspicious pattern** — both `windows-msgas.com` (a masquerading domain name) and the abused Cloudflare Quick Tunnel subdomain show the exact same behavior: `application/octet-stream` content type, randomly-generated URL paths, large unreadable binary payloads, repeated dozens of times. Two unrelated legitimate services would not coincidentally share this identical pattern — this is corroborating evidence of a single piece of malware using multiple channels.
3. **No legitimate web interaction produces this pattern.** Normal browsing, form submissions, or API calls do not use randomly-generated URL paths combined with raw octet-stream payloads of this volume and repetition.
4. **The abuse of Cloudflare's Quick Tunnel service is a known, real evasion technique** — attackers use `trycloudflare.com` specifically because it provides free, legitimate TLS and is difficult to block without impacting other legitimate Cloudflare-hosted traffic, making it an effective way to hide malicious infrastructure behind trusted services.

This case reinforces the same principle applied throughout `SOC-Triage-Practice`: no single indicator here is alone 100% conclusive, but the combination — masquerading domain naming, abused trusted infrastructure, non-standard content type, evasive URL structure, and high-volume repeated unreadable payloads across two independent channels — leaves no reasonable innocent explanation.

---

## What Would Change This Verdict to FP

- If either domain were confirmed as an authorized, documented third-party service integration with a legitimate business purpose for binary data transfer — no such justification is present here
- If the Cloudflare tunnel were confirmed as the organization's own authorized use of Quick Tunnels for legitimate remote access — not supported by the evidence (masquerading second domain present, no documented business context)

Neither applies — verdict stands as TP.

---

## Recommended Response Actions

- Isolate host `DESKTOP-5AVE44C` (`10.6.13.133`) from the network immediately
- Block `windows-msgas.com` and the specific Cloudflare tunnel subdomain at the firewall/DNS level (noting that blocking `trycloudflare.com` broadly may be impractical given legitimate uses — targeted subdomain/behavioral blocking is preferable)
- Attempt to identify the malware family based on this dual-channel exfiltration behavior for threat intelligence correlation
- Assume data has been exfiltrated given the volume and repetition observed; begin impact assessment
- Review other hosts on the network for the same masquerading-domain or Cloudflare-tunnel-abuse pattern

---

## Analysis Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Tool | Wireshark |
| Verdict | TP |
| Confidence | High |
| MITRE | T1041, T1071.001, T1090, T1036.005 |
