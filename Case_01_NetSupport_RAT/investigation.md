# Investigation — Case 01 (NetSupport Manager RAT)

## Step 1: Identify Traffic to the Known-Malicious IP

**Filter used:**
```
ip.addr == 45.131.214.85
```

**Result:** Multiple TCP/HTTP packets between internal host `10.2.28.88` and external IP `45.131.214.85`, port 443 (though traffic itself is plaintext HTTP, not TLS-encrypted — worth noting as an evasion-adjacent detail, since port 443 is normally associated with HTTPS).

**Finding:** 🔴 Internal host `10.2.28.88` is the infected client generating this traffic.

---

## Step 2: Confirm DNS Resolution

**Filter used:**
```
dns and ip.addr == 10.2.28.88
```

**Result:** A DNS query response confirms:
```
vadusa.xyz  A  45.131.214.85
```

**Finding:** 🔴 The infected host resolved the domain `vadusa.xyz` to the known-malicious IP — this was a deliberate domain lookup, not a coincidental or hardcoded connection. The internal domain controller observed answering DNS queries is `easyas123-dc.easyas123.tech` (the organization's internal AD/DNS server — not related to the malicious domain itself).

---

## Step 3: Follow the HTTP Stream

**Filter used:**
```
http and ip.addr == 45.131.214.85
```
Then: right-click a `POST /fakeurl.htm HTTP/1.1` packet → Follow → HTTP Stream.

**Result (key excerpt):**
```
POST http://45.131.214.85/fakeurl.htm HTTP/1.1
User-Agent: NetSupport Manager/1.3
Content-Type: application/x-www-form-urlencoded
Host: 45.131.214.85

CMD=POLL
INFO=1
ACK=1

HTTP/1.1 200 OK
Server: NetSupport Gateway/1.92 (Windows NT)
Content-Type: application/x-www-form-urlencoded

CMD=ENCD
ES=1
DATA=[encoded/obfuscated binary-looking data]
```

This exact `POST → CMD=POLL/ENCD response → POST → ...` cycle repeats multiple times across the stream.

**Findings:**
- 🔴 **User-Agent: `NetSupport Manager/1.3`** — a legitimate remote-support software User-Agent, but attackers commonly abuse legitimate remote-access tools specifically because their traffic is less likely to be flagged than custom malware. This matches the exact tool named in the SIEM alert.
- 🔴 **`CMD=POLL`** — the infected host repeatedly checking in with the remote server for instructions. This is textbook C2 beaconing behavior — a real user's browser does not send repeated POLL requests to a remote host.
- 🔴 **`CMD=ENCD` + obfuscated `DATA=`** — the server responds with encoded/unreadable command data, consistent with a C2 channel deliberately obscuring the actual instructions being relayed, rather than a transparent, legitimate remote-support session.
- 🔴 **`Server: NetSupport Gateway/1.92 (Windows NT)`** — confirms the remote infrastructure is genuinely running NetSupport's real server/gateway software, weaponized against a victim who did not request remote support.
- 🔴 **Repetition of the full request/response cycle** — a single request could be coincidental; the repeated poll-response pattern confirms an active, ongoing remote-control session rather than a one-off event.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| Destination IP reputation | Matches SIEM-flagged NetSupport RAT IP | 🔴 High |
| DNS resolution | Deliberate lookup of `vadusa.xyz` → malicious IP | 🔴 High |
| Application protocol | NetSupport RAT POLL/ENCD C2 protocol observed directly | 🔴 High |
| Data content | Obfuscated/encoded command data, not transparent | 🔴 High |
| Pattern | Repeated beaconing cycle across the capture | 🔴 High |
