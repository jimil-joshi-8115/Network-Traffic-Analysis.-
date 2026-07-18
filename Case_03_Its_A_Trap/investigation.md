# Investigation — Case 03 ("It's a Trap!")

## Step 1: Protocol Hierarchy Overview

**Path used:** Statistics → Protocol Hierarchy

**Result:** Traffic breakdown showed a mix of normal internal Windows/Active Directory protocols (SMB, Kerberos, LDAP, RPC — all between `10.6.13.x` addresses) alongside TCP/HTTP/TLS traffic to external hosts.

**Finding:** 🟡 The SMB/Kerberos/LDAP/RPC traffic between internal `10.6.13.x` hosts is normal domain-joined machine activity (the host authenticating against its own Active Directory environment) — correctly ruled out as noise rather than investigated further, consistent with the `Noise-Baselines/` discipline applied throughout `SOC-Triage-Practice`.

---

## Step 2: Rule Out Internal Noise, Isolate External Traffic

**Filter used:**
```
dns
```

**Result:** Most DNS activity resolved to the internal AD domain (`massfriction.com` — the organization's own domain, not malicious) and legitimate Microsoft Delivery Optimization infrastructure (`*.prod.do.dsp.mp.microsoft.com`).

**Finding:** 🟢 Correctly identified as legitimate background Windows/Microsoft activity — not the source of concern.

---

## Step 3: Identify Suspicious HTTP Traffic

**Filter used:**
```
http
```

**Result:** Two external destinations stood out, each receiving numerous `POST` requests with randomly-generated URL paths:
- `windows-msgas.com`
- `varying-rentals-calgary-predict.trycloudflare.com`

**Finding:** 🔴 Neither domain is legitimate Microsoft or expected business infrastructure:
- `windows-msgas.com` is a masquerading domain, deliberately named to resemble a genuine Microsoft/Windows service.
- `varying-rentals-calgary-predict.trycloudflare.com` uses Cloudflare's legitimate "Quick Tunnel" service (auto-generated random word-combination subdomains under `trycloudflare.com`) — a real, free Cloudflare feature increasingly abused by attackers to route malicious traffic through trusted infrastructure that is difficult to block at the network level.

---

## Step 4: Analyze the HTTP Request Pattern (windows-msgas.com)

**Follow → HTTP Stream on a POST request:**
```
POST /YSEpJj/CPZldd&293d91c90fd4799580711a44a9c358fa/R5n6W HTTP/1.1
Host: windows-msgas.com
Content-Length: 30496
Content-type: application/octet-stream

[unreadable binary data]
```

**Findings:**
- 🔴 `Content-type: application/octet-stream` — indicates raw binary data being transmitted, not a normal web form/page interaction.
- 🔴 Randomly-generated URL path with no logical website structure — commonly used to evade simple signature-based blocking, since each request appears unique.
- 🔴 ~30KB of fully unreadable binary content in the request body, consistent with encoded/encrypted stolen data or C2 command traffic.
- 🔴 This exact pattern (random path + octet-stream + large unreadable payload) repeats across many separate requests to the same host.

---

## Step 5: Analyze the HTTP Request Pattern (trycloudflare.com tunnel)

**Follow → HTTP Stream on a POST request:**
```
POST /Hy5DKjamtN5yw/qNQ9QK&3520b1594b8d4da1cb22cc2adbcda3f5/McDoVAqd HTTP/1.1
Host: varying-rentals-calgary-predict.trycloudflare.com
Content-Length: 30534
Content-type: application/octet-stream

[unreadable binary data]
```

**Finding:** 🔴 Identical pattern to Step 4 — same content type, same randomly-generated path structure, same volume and unreadability of payload, same repetition. Two independent destinations exhibiting the exact same behavior is strong corroborating evidence this is a single piece of malware using multiple exfiltration/C2 channels, not a coincidence or unrelated activity.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| Internal AD/domain traffic | Normal, correctly ruled out as noise | 🟢 None |
| Destination 1 (windows-msgas.com) | Masquerading domain name, no legitimate purpose | 🔴 High |
| Destination 2 (trycloudflare.com tunnel) | Abuse of legitimate Cloudflare Quick Tunnel infrastructure | 🔴 High |
| Content type | `application/octet-stream` on every request — raw binary, not normal web traffic | 🔴 High |
| URL structure | Randomly-generated paths on every request — evasion-consistent pattern | 🔴 High |
| Payload content | Fully unreadable/encoded binary data, ~30KB per request | 🔴 High |
| Pattern repetition | Same structure repeated dozens of times across both destinations | 🔴 High |
