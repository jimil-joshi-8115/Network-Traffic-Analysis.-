# Investigation — Case 05 (Nemotodes — Cracked APK Site)

## Step 1: Protocol Hierarchy and Conversations Overview

**Result:** Normal internal AD traffic (SMB, Kerberos, LDAP, RPC) between internal hosts on the `nemotodes` domain — correctly ruled out as noise, consistent with the internal-domain pattern seen in Cases 03/04 (`massfriction.com`, `bluemoontuesday.com`).

**External standout:** Host `10.11.26.183` shows four separate large TLS streams (6MB, 3MB, 3MB, 2MB) to a single IP, `193.42.38.139` — the clear top talker by volume.

---

## Step 2: Identify the Domain via SNI

**Filter used:**
```
ip.addr == 193.42.38.139 and tls.handshake.type == 1
```

**Result:** `SNI = modandcrackedapk.com`

**Finding:** 🔴 Unlike prior cases where domains were disguised to *look* legitimate (Cases 03/04), this domain openly signals its own nature — "mod and cracked APK" explicitly advertises pirated, illegally-modified Android software. No legitimate business justification exists for a corporate workstation to visit this site.

**Comparison check:** `173.222.49.101` resolved to `*.resources.office.net` via Akamai CDN (`e11271.dscg.akamaiedge.net`) — confirmed as legitimate Microsoft/Office infrastructure and correctly ruled out.

---

## Step 3: Confirm Repeated, Deliberate Visits

**Filter used:**
```
dns.qry.name contains "modandcrackedapk"
```

**Result:** Three separate DNS query/response pairs for `modandcrackedapk.com`, all resolving to `193.42.38.139`, occurring at approximately 35.6s, 37.2s, and 62.0s into the capture — each immediately followed by a large data transfer.

**Finding:** 🔴 Three separate, spread-out visits confirms sustained, deliberate engagement with this site rather than a single accidental click or stray connection.

---

## Step 4: Determine Data Flow Direction

**Path used:** Statistics → Conversations → TCP tab, examined Bytes A→B vs. Bytes B→A columns for the `193.42.38.139` streams.

**Result (largest stream, 6MB total):**
- Bytes A→B (host → server): 223 kB
- Bytes B→A (server → host): 5 MB

**Finding:** 🔴 Overwhelmingly download-heavy — the host is receiving large files from `modandcrackedapk.com`, not sending data out. This is the opposite direction pattern from Case_02's Lumma Stealer exfiltration, correctly distinguishing this as a malicious-download scenario rather than a data-theft scenario.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| Internal AD/CDN traffic | Normal, correctly ruled out as noise | 🟢 None |
| Destination domain | `modandcrackedapk.com` — explicitly pirated-software branding | 🔴 High |
| Visit pattern | 3 separate deliberate visits across the session | 🔴 High |
| Data direction | Download-heavy (5MB received vs. 223kB sent) | 🔴 High |
| Total downloaded volume | ~14MB across 3 large transfers | 🔴 High |
