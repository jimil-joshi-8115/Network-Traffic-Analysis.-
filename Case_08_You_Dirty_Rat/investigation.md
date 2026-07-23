# Investigation — Case 08 (You Dirty Rat! — RAT Fingerprinting)

## Step 1: Protocol Hierarchy Overview

**Result:** Frame total 11,562 packets / ~11.34MB.

| Protocol | % Packets | % Bytes |
|---|---|---|
| TCP (overall) | 97.5% | 2.0% (container) |
| **TLS** | 11.6% | **91.8%** (~10.4MB) |
| HTTP | ~0.03% (4 packets) | negligible |
| UDP/DNS/DHCP/Kerberos/LDAP/DCE-RPC/SMB/NetBIOS | remainder | remainder |

**Finding:** 🟡 TLS overwhelmingly dominates byte volume. HTTP traffic is minimal — only 4 packets total in the entire capture, meaning any cleartext activity is a very short list to review directly rather than needing extensive filtering.

---

## Step 2: Conversations Check (TCP)

**Result (sorted by Bytes, descending):** Top three external IPs by volume — `199.232.196.209` (5MB+3MB+2MB across three streams, ~10MB combined), `185.199.110.133` (834KB), plus a long tail of much smaller (10-70KB) TLS conversations.

**Finding:** 🟡 The largest bandwidth consumers needed identity confirmation before assuming malicious intent, given the byte volume closely matched the 91.8% TLS total from Protocol Hierarchy.

---

## Step 3: Identify Top Bandwidth Consumers via SNI/DNS

**Filters used:**
```
ip.addr == 199.232.196.209 and tls.handshake.type == 1
ip.addr == 185.199.110.133 and tls.handshake.type == 11
dns.flags.response == 1
```

**Result:**
- `199.232.196.209` → SNI `repo1.maven.org` (fronted via `dualstack.sonatype.map.fastly.net`) — **Maven Central**, legitimate Java package repository.
- `185.199.110.133` → certificate for `objects.githubusercontent.com` — **GitHub's CDN**, legitimate.
- Full DNS response review showed otherwise-expected entries: `g.live.com`, `oneclient.sfx.ms`, `client.wns.windows.com`, `assets.msn.com`, `github.com`, `repo1.maven.org`, `th.bing.com`, `settings-win.data.microsoft.com`, `login.microsoftonline.com`, and a failed `wpad.wiresharkworkshop.online` lookup (routine WPAD auto-proxy probe, NXDOMAIN).

**Finding:** 🟢 Both top-bandwidth destinations and the bulk of resolved domains are legitimate developer-workstation and Windows/Microsoft background traffic — ruled out as noise. This confirmed the actual infection indicator would be small in volume, not a bandwidth outlier.

**One anomalous DNS entry:** 🔴 `ip-api.com` — a free IP-geolocation lookup service commonly abused by malware for victim/environment fingerprinting immediately after infection.

---

## Step 4: HTTP Traffic Review

**Filter used:**
```
http
```

**Result:** Only two real HTTP exchanges in the entire capture:
1. `GET /connecttest.txt` to `a1961.g2.akamai.net` — Windows' built-in NCSI (Network Connectivity Status Indicator) check. Benign, automatic OS behavior.
2. **`GET /json/` to `ip-api.com`** — the geolocation lookup.

---

## Step 5: ip-api.com Request/Response Analysis

**Filter used:**
```
http.host == "ip-api.com"
```

**Request:**
```
GET /json/ HTTP/1.1
Host: ip-api.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36
Connection: close
```

**Response:**
```
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
{"status":"success","country":"United States","countryCode":"US","region":"TX","regionName":"Texas","city":"Austin","zip":"78752","lat":30.2095,"lon":-97.7972,"timezone":"America/Chicago","isp":"Google Fiber, Inc.","org":"Google Fiber","as":"AS16591 Google Fiber, Inc.","query":"136.49.34.127"}
```

**Finding:** 🔴 Two independent red flags on this single request:
1. **Stale, hardcoded User-Agent** — `Chrome/73.0.3683.86` corresponds to a Chrome release from early 2019, five years out of date relative to this 2024 capture. No genuine browser session would present this version; this is consistent with a script/malware sample using a hardcoded fake UA string to blend in as ordinary browser traffic (same technique observed with different fake UAs in Cases 06/07).
2. **One-shot fingerprinting call** (`Connection: close`, single request/response, no follow-up session) returning the host's true public IP, city-level geolocation, and ISP/ASN. This is a well-documented RAT/loader behavior pattern: checking whether the infected environment is a real residential/corporate victim (as confirmed here — Google Fiber, Austin TX) versus a cloud/hosting-provider or sandbox IP range, before deciding whether/how to proceed with further malicious activity.

---

## Step 6: C2 Channel Isolation — Open Item

**Attempted:** Sorting TCP Conversations by Duration (descending) to locate a long-lived, low-bandwidth connection consistent with an active C2 channel, as distinct from the one-shot fingerprinting call.

**Result:** ⚠️ Not conclusively completed this session — the Duration-sorted view was not captured before wrapping up. This is called out explicitly as an unresolved technical step, not glossed over.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| Internal AD/OS telemetry | Normal, correctly ruled out as noise | 🟢 None |
| Top-bandwidth destinations (Maven, GitHub CDN) | Legitimate developer tooling | 🟢 None |
| `ip-api.com` lookup | Environment/victim fingerprinting call | 🔴 High |
| User-Agent on that request | Stale/hardcoded Chrome 73 (2019), inconsistent with capture date | 🔴 High |
| Actual C2 channel | Not conclusively isolated this session | ⚠️ Open item |
