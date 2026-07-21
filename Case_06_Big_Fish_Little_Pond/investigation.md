# Investigation — Case 06 (Big Fish in a Little Pond — Loader C2)

## Step 1: Protocol Hierarchy Overview

**Result:** Frame total 5,091 packets / ~2.05MB.

| Protocol | % Packets | % Bytes |
|---|---|---|
| TCP (overall) | 82.9% | 4.3% (container) |
| **TLS** | 14.5% | **62.1%** (~1.27MB) |
| HTTP | 2.2% | 1.5% (~30KB) |
| UDP/DNS/DHCP/Kerberos/LDAP/DCE-RPC/SMB/NetBIOS | remainder | remainder |

**Finding:** 🟡 The bulk of the SMB/Kerberos/LDAP/DCE-RPC/NetBIOS/NTP/DHCP traffic is normal internal Active Directory chatter on the `bepositive.com` domain (matches AD DC `172.17.0.17`) — correctly ruled out as noise, consistent with prior cases. TLS dominates by byte volume (62.1%) despite being a small fraction of packet count, meaning a handful of TLS streams carry most of the data. HTTP is comparatively tiny (~30KB total), so any cleartext C2/loader activity is small individual requests rather than bulk transfer.

**Open item:** ⚠️ The specific destination(s) responsible for the 62.1% TLS byte volume were not conclusively isolated during this session (sort-order issue in the Conversations window). This is called out explicitly below as an unresolved technical question that does not change the verdict but should be revisited.

---

## Step 2: Conversations Check (TCP)

**Result:** Host `172.17.0.99` (`DESKTOP-RNVO9AT.bepositive.com`) shows numerous small, repeated TCP streams (~749 bytes / ~522 bytes each) to a single external IP, **`79.124.78.197`**, on port 80 — many separate stream IDs (75, 113, 139, 142, 147–151, 56, 63, 68, 71, 86, 89...) spread across a wide time range (Rel Start ~63s through ~1208s+).

**Finding:** 🔴 Many near-identical-size, repeated TCP connections to the same external IP over an extended period is the signature of **beaconing/check-in behavior**, similar in concept to Case_04's beacon but different in mechanism and direction (see below).

---

## Step 3: Confirm No Legitimate Domain Resolution

**Filter used:**
```
ip.addr == 79.124.78.197
```

**Result:** First packets to `79.124.78.197` are a raw TCP three-way handshake (SYN/SYN-ACK/ACK) with **no preceding DNS query** for any domain resolving to this IP. Wireshark's displayed "78.197.static.net.d..." label is a **reverse-DNS PTR/ISP label**, not evidence of a forward lookup by the client.

**Finding:** 🔴 The infected host connects **straight to a raw IP address**, with no legitimate domain involved — same red flag pattern as Case_04's raw-IP download stage. No further DNS resolution to this IP was found.

---

## Step 4: HTTP Stream Analysis — C2 Check-in Protocol

**Filter used:**
```
ip.addr == 79.124.78.197 and http.request.method == "POST"
```

**Result:** 49 POST requests to `79.124.78.197` spanning **~155.9s to ~1208.8s** (~17.5 minutes) — sustained, long-duration activity, not a one-off connection.

- 48 of these are `POST /foots.php HTTP/1.1`, each with `Content-Type: application/octet-stream`, `Content-Encoding: binary`, varying small `Content-Length` values (e.g., 94, 112, 40, 497, 516, 443 bytes), and encrypted/binary request bodies (non-readable).
- One outlier: `POST /index.php HTTP/1.1` (frame 2236, Content-Length 159) — a different endpoint mixed into the sequence.
- **User-Agent** on all requests: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729)` — an internally inconsistent, spoofed UA string (claims IE7/Trident engine on a Windows NT 10.0 host; no real modern browser presents this way).
- Server responses: `nginx`, `200 OK`, `Transfer-Encoding: chunked` — consistent, live C2 panel on the other end.

**Finding:** 🔴 Sustained encrypted C2 beaconing/exfil channel, ~17.5 minutes of repeated small-payload POSTs with a spoofed User-Agent.

---

## Step 5: Loader Registration/Config Handshake

**Filter used:** Follow → HTTP Stream on an early GET request to `79.124.78.197`.

**Result:**
```
GET /index.php?id=&subid=qIOuKk7U HTTP/1.1
Host: 79.124.78.197
```
Server response body:
```
HckDcK0czXjaq48jVHNn|qIOuKk7U|http://79.124.78.197/index.php|
```
Followed immediately by:
```
POST /index.php HTTP/1.1
Content-Length: 105

[encrypted/binary body]
```

**Finding:** 🔴 The `id`/`subid` query-string pattern combined with a pipe-delimited token/subid/callback-URL response is characteristic of a **PHP-based loader/stealer C2 panel** registration handshake — the server is issuing the infected host a bot ID (`HckDcK0czXjaq48jVHNn`) tied to its session (`subid=qIOuKk7U`) and confirming its own callback URL. The subsequent encrypted POST is the client reporting back (likely host recon data or the start of an exfil/module-fetch cycle).

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| Internal AD traffic (`bepositive.com`) | Normal, correctly ruled out as noise | 🟢 None |
| Destination | `79.124.78.197` — raw IP, no domain resolution | 🔴 High |
| Protocol pattern | Loader registration handshake (`id`/`subid` → pipe-delimited config) | 🔴 High |
| Ongoing traffic | 49 encrypted POSTs to `/foots.php` over ~17.5 min | 🔴 High |
| User-Agent | Spoofed/inconsistent MSIE7-Trident string | 🔴 High |
| TLS volume (62.1% of bytes) | Destination not conclusively isolated this session | ⚠️ Open item |
