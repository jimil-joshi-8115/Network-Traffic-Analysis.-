# Investigation — Case 07 (WarmCookie — Fake FedEx Invoice)

## Step 1: Protocol Hierarchy Overview

**Result:** Frame total 18,189 packets / ~11.67MB.

| Protocol | % Packets | % Bytes |
|---|---|---|
| TCP (overall) | 84.5% | 2.7% (container) |
| **TLS** | 11.0% | **42.6%** (~4.97MB) |
| **Unclassified "Data"** | 0.9% | **23.7%** (~2.77MB) |
| HTTP | 3.6% | 5.9% (~683KB) |
| UDP/DNS/DHCP/Kerberos/LDAP/DCE-RPC/SMB/NetBIOS/QUIC | remainder | remainder |

**Finding:** 🟡 Internal AD/Kerberos/SMB/LDAP/DCE-RPC/NetBIOS traffic ruled out as normal domain noise. TLS and a large unclassified "Data" segment dominate byte volume — flagged for follow-up. QUIC traffic (11.8% of packets) was later confirmed as legitimate Bing/Edge/Akamai telemetry (see Step 5) and ruled out.

---

## Step 2: Conversations Check (TCP)

**Result (sorted by Bytes, descending):**

| Rank | IP | Port | Bytes | Notes |
|---|---|---|---|---|
| 1 | `104.21.55.70` | 80 | 3MB | Cloudflare |
| 2 | `72.167.170.159` | 80 | 1MB | Cloudflare |
| 3 | `23.220.103.18` | 443 | 702KB | Akamai (later ruled out — see Step 5) |

**Finding:** 🔴 Top two talkers are both Cloudflare-fronted IPs, later confirmed to be the same phishing domain resolved across two subdomains.

---

## Step 3: Domain Identification via DNS

**Filter used:**
```
dns.qry.name contains "checkfedex"
```

**Result:** Two subdomains identified — `quote.checkfedexexp.com` and `business.checkfedexexp.com` — both resolving to the same two IPs: `104.21.55.70` and `172.67.170.159`, matching the top Conversations entries.

**Finding:** 🔴 `checkfedexexp.com` is a typosquat impersonating FedEx ("check fedex express"), a classic courier-brand phishing lure. Both subdomains share Cloudflare-fronted infrastructure, consistent with a phishing kit hiding its true backend host behind a CDN.

---

## Step 4: HTTP Request/Response — Payload Delivery

**Filter used:**
```
ip.addr == 104.21.55.70 and http
```

**Result — Request:**
```
GET /managements?16553a25e45250a41fd5&endeds=MIGpq&JStx=59bf050d37df88a9-...&Ld=9d7502d88d752a27b1d00587309184b5a215 HTTP/1.1
Host: quote.checkfedexexp.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/127.0.0.0 ... Edg/127.0.0.0
```

**Result — Response:**
```
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Transfer-Encoding: chunked
Content-Disposition: attachment; filename="Invoice 876597035_003.zip"
Server: cloudflare
```

Response body begins with `PK..` (ZIP file magic bytes), and the archive contains a file named:
```
Invoice-876597035-003-8331775-8334138.js
```

**Finding:** 🔴 A genuine browser session (real Chrome/Edge UA, not a scripted/automated request) downloads a ZIP file disguised as a courier invoice, served with a forced-download header. Inside the ZIP is a `.js` script, not a document — the actual payload, disguised behind an invoice-themed filename. This matches WarmCookie's documented delivery pattern (fake courier/invoice lure → ZIP → obfuscated JS loader).

**Note:** The tracking-style query parameters (`endeds=`, `JStx=`, `Ld=`) on the initial GET request are consistent with phishing-kit/redirect-chain instrumentation rather than a normal business URL structure.

---

## Step 5: Ruling Out `23.220.103.18`

**Filter used:**
```
ip.addr == 23.220.103.18 and tls.handshake.type == 1
```

**Result:** Client Hello SNI values of `www.bing.com` and `edgeservices.bing.com`; associated QUIC traffic resolves to Akamai infrastructure (`e86303.dscx.akamaiedge.net`).

**Finding:** 🟢 Legitimate Bing/Microsoft Edge browser telemetry over Akamai CDN — correctly ruled out as unrelated to the incident.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| Internal AD traffic | Normal, correctly ruled out as noise | 🟢 None |
| `23.220.103.18` (Akamai/Bing) | Legitimate browser telemetry, ruled out | 🟢 None |
| Destination domain | `checkfedexexp.com` — FedEx typosquat, Cloudflare-fronted | 🔴 High |
| Delivery mechanism | Forced ZIP download disguised as invoice | 🔴 High |
| Payload | Obfuscated `.js` file bundled inside the ZIP | 🔴 High |
| Unclassified "Data" (23.7% of bytes) | Consistent with large chunked HTTP response body (ZIP transfer) not cleanly reassembled by dissector | 🟡 Explained, not separately isolated |
