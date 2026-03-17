# Pi-Blocker: MITRE D3FEND Defense Overview
**Author:** Conor McFadden  
**Framework:** MITRE D3FEND  
**Platform:** Raspberry Pi Zero 2 W  
**Language:** C (Raw Sockets)

---

## What is MITRE D3FEND?

MITRE D3FEND is a knowledge graph of cybersecurity countermeasures — the defensive counterpart to MITRE ATT&CK. Where ATT&CK catalogs offensive techniques adversaries use, D3FEND catalogs the defensive techniques that detect, isolate, deceive, evict, or harden systems against those techniques.

D3FEND organizes defenses into five high-level tactics:
- **Harden** — reduce attack surface
- **Detect** — identify malicious activity
- **Isolate** — limit blast radius
- **Deceive** — mislead adversaries
- **Evict** — remove adversary presence

Pi-Blocker implements **Detect** and **Isolate** techniques across all 7 OSI layers.

---

## Defense Map

| Layer | OSI Layer | D3FEND Technique | ATT&CK Countered |
|---|---|---|---|
| 7 | Application | D3-DNSDL — DNS Denylisting | T1071.004 |
| 7 | Application | D3-HTTPA — HTTP Application Filtering | T1071.001 |
| 6 | Presentation | D3-TLSIC — TLS ClientHello Inspection | T1573 |
| 5 | Session | D3-CSLL — Connection Session Limit | T1499 |
| 4 | Transport | D3-NTCD — Network Traffic Community Deviation | T1046 |
| 3 | Network | D3-ITF — Inbound Traffic Filtering | T1590 |
| 2 | Data Link | D3-AAF — Authentication Anomaly Detection | T1557.002 |
| 1 | Physical | D3-NTA — Network Traffic Analysis | T1200 |

---

## Layer 7 — D3-DNSDL: DNS Denylisting

**Technique:** Intercept DNS queries and return REFUSED for known malicious or unwanted domains.

**Implementation:**
- Raw UDP socket on port 53
- 70,000+ domain blocklist loaded at startup
- Binary search — O(log n) lookup
- Subdomain matching — blocking `evil.com` blocks `sub.evil.com` automatically
- Manually implements RFC 1035 DNS parsing including pointer-based name decompression
- Returns REFUSED response code for blocked domains

**What it counters:**
- C2 domains — malware phoning home via DNS
- Ad networks — the original use case
- Domain generation algorithm (DGA) domains if present in blocklist
- DNS tunneling to known bad domains

**D3FEND relationship:** `d3f:DNSDenylisting` → counters `attack:T1071.004 (Application Layer Protocol: DNS)`

---

## Layer 7 — D3-HTTPA: HTTP Application Filtering

**Technique:** Inspect HTTP requests at the application layer and block requests to known bad destinations.

**Implementation:**
- TCP socket on port 8080, multi-threaded (pthread per connection)
- Parses HTTP request line and Host header
- Checks hostname against shared blocklist
- Returns 403 Forbidden for blocked domains
- Handles both plain HTTP (GET/POST) and HTTPS tunneling (CONNECT method)
- Port extraction via `strtol()` from Host header

**What it counters:**
- HTTP-based C2 traffic
- Direct IP requests that bypass DNS filtering
- Malware using HTTP for data exfiltration

**Known gap (documented):** The CONNECT handler lacked destination validation — allowing SSRF to localhost. Fix: validate CONNECT destinations against loopback and RFC 1918 ranges before tunneling.

**D3FEND relationship:** `d3f:HTTPApplicationFirewall` → counters `attack:T1071.001 (Application Layer Protocol: Web Protocols)`

---

## Layer 6 — D3-TLSIC: TLS ClientHello Inspection

**Technique:** Inspect the unencrypted TLS ClientHello message before the handshake completes to enforce TLS policy.

**The window:** The TLS ClientHello is sent in cleartext before encryption is established. Once the handshake completes, all payload is opaque. The ClientHello is the only opportunity for network-level TLS inspection.

**Implementation:**
- Raw IP socket (IPPROTO_TCP), monitors ports 443 and 8080
- Parses TLS record header → handshake header → ClientHello fields
- Multi-threaded — each ClientHello packet spawns a thread
- Policy engine evaluates five checks:

| Check | Threshold | Verdict |
|---|---|---|
| SNI present | Must be present | ALERT if missing |
| TLS version | Minimum 0x0303 (TLS 1.2) | BLOCK if below |
| ALPN value | Must be h2 or http/1.1 | ALERT if exotic |
| Extension count | Threshold: configurable | ALERT if exceeded |
| ClientHello size | Threshold: configurable | ALERT if oversized |

**Enforcement:** TCP RST injection toward client using `rst_inject()` — actively terminates the connection before the handshake completes.

**Known limitation:** Packet-based inspection only. A ClientHello fragmented across multiple TCP segments bypasses inspection. Full stream reassembly is a planned improvement.

**D3FEND relationship:** `d3f:TLSInspection` → counters `attack:T1573 (Encrypted Channel)`

---

## Layer 5 — D3-CSLL: Connection Session Limit

**Technique:** Track connection establishment rates per source IP and block sources that exceed normal thresholds.

**Implementation:**
- Monitors TCP SYN packets via raw socket
- Hash table with 1021 buckets (prime, minimizes collision clustering), chaining for collision resolution
- Tumbling 60-second window per source IP
- Threshold: 20 SYNs from same IP within window → block
- Signed return convention: negative = flood detected, positive = allowed, 0 = insert failed
- Full mutex protection on hash table — thread-safe across concurrent packet threads
- Blocked IPs added to PI_BLOCKER iptables chain via `block_ip()`

**What it counters:**
- SYN flood DoS attacks (T1499)
- Aggressive connection-based scanners
- Connection table exhaustion attacks

**Known limitation:** Per-source-IP only. A distributed SYN flood from many sources — each sending only a few SYNs — stays under the per-IP threshold. Subnet-level aggregate tracking would address this.

**D3FEND relationship:** `d3f:ConnectionAttemptLimiting` → counters `attack:T1499 (Endpoint Denial of Service)`

---

## Layer 4 — D3-NTCD: Network Traffic Community Deviation

**Technique:** Detect statistically anomalous traffic patterns — specifically port scanning behavior — by tracking unique destination ports per source over time.

**Implementation:**
- Raw socket monitors TCP flags per packet
- Detects four scan types by TCP flag inspection:
  - **SYN scan** — only SYN flag set (0x02)
  - **NULL scan** — no flags set (0x00)
  - **XMAS scan** — FIN+PSH+URG set (0x29)
  - **FIN scan** — only FIN set (0x01)
- Circular buffer (size 32) tracks unique destination ports per source IP
- 10-second detection window
- Threshold: 16 unique ports → block + RST inject
- Active RST injection disrupts the scan in progress

**What it counters:**
- Network reconnaissance (T1046)
- Service discovery attempts
- Stealth scan variants

**Known limitation:** Fixed 10-second window. A scan with 15+ second delays between probes stays under the threshold — exploited during the attack simulation. Adaptive/cumulative scoring would be more robust.

**D3FEND relationship:** `d3f:NetworkTrafficCommunityDeviation` → counters `attack:T1046 (Network Service Discovery)`

---

## Layer 3 — D3-ITF: Inbound Traffic Filtering

**Technique:** Filter inbound traffic based on IP reputation — blocking known malicious source IPs before any connection is established.

**Implementation:**
- AF_PACKET raw socket with ETH_P_IP — sees forwarded traffic, not just destined-for-Pi traffic
- Manually skips Ethernet header to reach IP header
- Two threat intelligence feeds loaded at startup:
  - **Feodo Tracker** — active botnet C2 server IPs (Emotet, TrickBot, QakBot)
  - **Emerging Threats** — broader malicious IP ranges
- Supports both single IPs (stored as /32) and CIDR ranges
- CIDR matching: `mask = ~0u << (32 - prefix); return (src & mask) == (net & mask)`
- Entries sorted by network address at load time via qsort
- `reputation/update.sh` pulls fresh feeds automatically
- Maximum 4096 entries; blocked IPs added to PI_BLOCKER chain

**What it counters:**
- Known C2 server communications — severs malware's command channel even if malware is already on network
- Traffic from known malicious infrastructure
- Botnet participation

**Known limitation:** Linear scan O(n). Binary search would reduce to O(log n) — approximately 12 comparisons vs up to 4096 for a full list.

**D3FEND relationship:** `d3f:InboundTrafficFiltering` → counters `attack:T1590 (Gather Victim Network Information)`

---

## Layer 2 — D3-AAF: ARP Cache Poisoning Detection

**Technique:** Monitor ARP traffic on the local segment to detect when a known IP-to-MAC mapping changes unexpectedly, indicating ARP cache poisoning.

**Background:** ARP is unauthenticated. Any device can send a gratuitous ARP reply claiming any IP, poisoning the ARP caches of other devices on the segment and enabling man-in-the-middle interception.

**Implementation:**
- AF_PACKET socket filtering on ETH_P_ARP (0x0806)
- Monitors ARP replies only (opcode == 2)
- Validates packet fields: htype==1 (Ethernet), ptype==0x0800 (IPv4), hlen==6, plen==4
- Maintains hash table of IP → MAC[6] mappings with stale entry pruning (300-second TTL)
- On new IP: learn and store mapping
- On known IP: compare SHA (sender hardware address) against stored MAC
- Mismatch → ALERT with old MAC and new MAC logged
- `check_arp_spoof()` returns: 1=spoof detected, 0=ok/learned, -1=table full

**What it counters:**
- ARP spoofing / cache poisoning (T1557.002)
- Man-in-the-middle setup on local segment
- Rogue device impersonating gateway

**D3FEND relationship:** `d3f:ARPCachePoisoningDetection` → counters `attack:T1557.002 (ARP Cache Poisoning)`

---

## Layer 1 — D3-NTA: Physical Link State Monitoring

**Technique:** Monitor the physical network interface for unexpected link state changes that may indicate physical tampering or tap installation.

**Background:** Most security stacks stop at Layer 2. Physical attacks — inline taps, cable swaps, rogue hardware insertions — cause brief carrier disruptions during installation that are visible at Layer 1 before any malicious traffic is observed.

**Implementation:**
- AF_NETLINK socket (NETLINK_ROUTE), subscribed to RTMGRP_LINK multicast group
- `recvmsg()` blocking loop — receives kernel RTM_NEWLINK events
- Parses `ifinfomsg.ifi_flags` from NLMSG_DATA():
  - `IFF_UP + IFF_RUNNING` → LINK_STATE_UP (carrier present)
  - `IFF_UP` only → LINK_STATE_DOWN (carrier lost — potential tap)
  - Neither → LINK_STATE_DISABLED
- Tracks `flap_count` per interface
- Alert cooldown: LINK_ALERT_COOLDOWN = 10 seconds (prevents log flooding)
- Detection-only layer — no active enforcement possible at physical layer

**What it counters:**
- Physical network tap installation (T1200)
- Cable manipulation
- Rogue hardware insertion

**D3FEND relationship:** `d3f:NetworkTrafficAnalysis` → counters `attack:T1200 (Hardware Additions)`

---

## Shared Enforcement Infrastructure

All layers share a common enforcement library (`common/enforce.c`) ensuring consistent, deduplicated blocking across the stack.

### PI_BLOCKER iptables Chain
```
iptables -N PI_BLOCKER
iptables -I FORWARD -j PI_BLOCKER
iptables -I INPUT -j PI_BLOCKER
```
Dedicated chain — flush and delete on exit without touching other rules.

### Enforcement Functions
| Function | Action |
|---|---|
| `block_ip(src_ip)` | iptables -A PI_BLOCKER -s X -j DROP |
| `block_port(port, proto)` | iptables -A PI_BLOCKER -p X --dport N -j DROP |
| `block_proto(proto)` | iptables -A PI_BLOCKER -p X -j DROP |
| `rst_inject(fd, src, sport, dst, dport, ack)` | Craft and send TCP RST with RFC 793 pseudo-header checksum |

Hash tables for each block type (1021 buckets, prime) prevent duplicate iptables rules. `pthread_once` ensures one-time initialization. All operations mutex-protected.

### Threading Model
Every layer uses the same pattern:
```c
pthread_create(&thread_id, NULL, handle_function, task);
pthread_detach(thread_id);
```
Main loop stays non-blocking. Shared data structures protected by `pthread_mutex_t`.

### Logging Format
Every decision across every layer logs in identical format:
```
[YYYY-MM-DD HH:MM:SS] [LAYER_X] [PROTO] [ACTION] <fields> d3fend=D3-XXXX attck=TXXXX
```
MITRE technique tags are inline in every log entry — no separate lookup required during incident review.

---

## D3FEND Tactic Coverage

| Tactic | Coverage |
|---|---|
| **Harden** | Partial — TLS version enforcement (L6), port blocking (L4) |
| **Detect** | Full — all 7 layers generate detection events |
| **Isolate** | Full — iptables blocking at L3/L4/L5, RST injection at L4/L6 |
| **Deceive** | Not implemented |
| **Evict** | Not implemented |

Pi-Blocker is primarily a **Detect + Isolate** stack. Deceive (honeypots, decoys) and Evict (active removal of adversary presence) are natural next phases.

---

## Known Gaps and Mitigations

| Gap | Affected Layer | Mitigation |
|---|---|---|
| CONNECT destination not validated | L7 | Validate against loopback + RFC 1918 before tunneling |
| No inter-layer communication | All | Shared block state registry across all layers |
| Packet-based TLS inspection | L6 | Full TCP stream reassembly |
| Fixed scan detection window | L4 | Adaptive/cumulative scoring |
| Per-IP SYN threshold only | L5 | Subnet-level aggregate tracking |
| Linear reputation scan | L3 | Binary search on sorted list |
| No JA3 fingerprinting | L6 | Hash TLS ClientHello fields for malware family identification |