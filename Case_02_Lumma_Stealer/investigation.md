# Investigation — Case 02 (Lumma Stealer)

## Step 1: Protocol Hierarchy Overview

**Path used:** Statistics → Protocol Hierarchy

**Result:** 98.3% of the capture is TLS traffic — nearly all encrypted. Unlike Case_01 (plaintext HTTP), content-level inspection is not possible here; analysis must rely on connection metadata (timing, volume, direction, SNI).

---

## Step 2: Identify Anomalous Conversations

**Path used:** Statistics → Conversations → TCP tab, sorted by Bytes

**Result:** Internal host `10.1.21.58` shows a distinct pattern to external IP `153.92.1.49`:
- 9+ separate short TCP streams (~20 packets, ~4-6 KB each) to the same IP
- 1 large stream (Stream ID 125): 1,721 packets, ~2 MB

**Finding:** 🔴 This is structurally different from the normal browsing conversations visible to Google/CDN IPs (`192.178.220.102`, `173.194.208.x`) in the same capture, which show single, larger, more typical sessions. Repeated fresh connections to one destination plus one large transfer is an anomalous pattern worth isolating.

---

## Step 3: Identify the Domain via SNI

**Filter used:**
```
ip.addr == 153.92.1.49
```

Inspected the TLS Client Hello packet's **Server Name Indication (SNI)** field.

**Result:** `SNI = whitepepper.su`

**Finding:** 🔴 Even though the connection is TLS-encrypted, the SNI field is sent in plaintext during the handshake and reveals the destination domain. `.su` (legacy Russian TLD) combined with a random, non-business-sounding name has no legitimate explanation for a normal user session.

---

## Step 4: Confirm Connection Timing (Burst Pattern)

**Filter used:**
```
ip.addr == 153.92.1.49 and tls.handshake.type == 1
```

**Result:** 13 separate Client Hello packets, all within approximately a 30-second window (capture time 92.5s → 122.0s).

**Finding:** 🔴 Rapid, repeated fresh TLS connections within a tight window is a burst pattern — distinct from Case_01's steady, spaced-out beaconing (RAT polling). This burst behavior is consistent with an infostealer rapidly collecting and transmitting multiple categories of local data in quick succession.

---

## Step 5: Analyze the Large Transfer (Stream 125)

**Path used:** Conversations window → select Stream 125 → Follow Stream (TCP/TLS)

**Result:** Encrypted binary content, as expected. `whitepepper.su` visible in plaintext during the certificate exchange portion, confirming the destination. Stream statistics show **1,035 client packets vs. only 6 server packets**.

**Finding:** 🔴 The overwhelming client-to-server packet imbalance indicates the infected host is predominantly **sending** data outward, not receiving it — the fingerprint of data exfiltration rather than normal content download (which would show the reverse imbalance).

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| Protocol overview | 98.3% TLS, content not readable | Informational |
| Conversation pattern | Repeated short connections + one large transfer to one IP | 🔴 High |
| SNI / domain | `whitepepper.su`, `.su` TLD, no legitimate purpose | 🔴 High |
| Connection timing | 13 connections within ~30 seconds — burst pattern | 🔴 High |
| Data direction | 1,035 client packets vs. 6 server packets — outbound-heavy | 🔴 High |
