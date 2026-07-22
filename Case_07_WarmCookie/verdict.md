# Verdict — Case 07 (WarmCookie — Fake FedEx Invoice)

## 🔴 Verdict: TRUE POSITIVE

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Phishing | T1566 | Fake FedEx-branded invoice lure serving a malicious download |
| User Execution: Malicious File | T1204.002 | Victim expected to open a `.js` file disguised as an invoice document |
| Masquerading | T1036 | Typosquat domain (`checkfedexexp.com`) impersonating FedEx; ZIP filename disguised as an invoice |
| Ingress Tool Transfer | T1105 | Delivery of the WarmCookie loader payload via forced ZIP download |

---

## Justification

1. **Typosquat/impersonation domain** — `checkfedexexp.com` closely mimics FedEx branding with no legitimate association to the real company; both observed subdomains (`quote.` and `business.`) resolve to Cloudflare-fronted infrastructure, a common technique to obscure the true backend and lend unwarranted legitimacy via valid HTTPS.
2. **Forced malicious download disguised as a legitimate document** — the server responded to a real browser request with a forced-download ZIP named to look like a courier invoice (`Invoice 876597035_003.zip`), rather than rendering a normal web page.
3. **Payload is a disguised script, not a document** — the ZIP's contents (`Invoice-876597035-003-8331775-8334138.js`) is a JavaScript file, not any kind of invoice/PDF/document — a strong indicator of intent to deceive the victim into execution, consistent with WarmCookie's documented delivery chain.
4. **Real browser session confirms a live human interaction** — the request carried a genuine, current Chrome/Edge User-Agent, indicating an actual user reached this page (as opposed to automated scanning), consistent with a successful phishing click-through.
5. **No legitimate explanation exists** for a corporate workstation retrieving a JS-in-ZIP payload from a courier-impersonating typosquat domain.

Consistent with reasoning applied in prior cases (e.g., Case_04's disguised PowerShell delivery, Case_06's loader C2 handshake): a convincing brand-impersonation lure paired with a disguised executable payload is sufficient to close as TP, even without direct confirmation of the script's subsequent runtime behavior on the host.

---

## What Would Change This Verdict to FP

- If `checkfedexexp.com` were confirmed as an authorized phishing-simulation/security-awareness test conducted by IT/security staff — no such context is present here.
- If the downloaded `.js` file could be shown to be benign despite its disguised delivery — implausible given the delivery mechanism (forced download, invoice-themed filename, non-document file type) and the domain's clear impersonation intent.

No such justification applies — verdict stands as TP.

---

## Recommended Response Actions

- Isolate the affected host from the network and check for confirmation of the ZIP/JS file execution via EDR/endpoint logs
- Extract and sandbox-analyze `Invoice-876597035-003-8331775-8334138.js` to confirm WarmCookie loader behavior and identify any subsequent C2 infrastructure
- Block `checkfedexexp.com` (all subdomains) and associated Cloudflare IPs (`104.21.55.70`, `172.67.170.159`) at DNS/proxy/firewall level
- Review email gateway logs for the original phishing lure (subject line, sender, attachment/link) to identify other potentially targeted users
- User awareness follow-up: reinforce recognition of courier/invoice-themed phishing lures and forced ZIP downloads
- Revisit remaining TLS traffic volume post-incident to confirm whether any of it reflects follow-on C2 activity from the JS payload

---

## Analysis Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Tool | Wireshark |
| Verdict | TP |
| Confidence | High |
| MITRE | T1566, T1204.002, T1036, T1105 |
| Open Items | Downstream C2 behavior of the `.js` payload not directly observed in this session |
