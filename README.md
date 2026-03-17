# Pi-Blocker 🛡️

A 7-layer OSI network security stack built in C using raw sockets, running on a Raspberry Pi Zero 2 W. Implements MITRE D3FEND defensive techniques at every OSI layer — from physical link monitoring up to DNS and HTTP application filtering. Includes a full MITRE ATT&CK attack simulation documenting what the stack catches and what it misses.

> Started as a DNS ad blocker. Became something more.

---

## What It Does

| Layer | Protocol | D3FEND Technique | What It Defends Against |
|---|---|---|---|
| L7 | DNS + HTTP | D3-DNSDL, D3-HTTPA | C2 domains, ad networks, HTTP-based malware |
| L6 | TLS | D3-TLSIC | Deprecated TLS, missing SNI, C2 tunneling |
| L5 | TCP | D3-CSLL | SYN flood DoS, connection exhaustion |
| L4 | TCP | D3-NTCD | Port scans (SYN, NULL, XMAS, FIN) |
| L3 | IP | D3-ITF | Known malicious IPs, botnet C2 servers |
| L2 | ARP | D3-AAF | ARP spoofing, MITM attacks |
| L1 | Physical | D3-NTA | Physical taps, link state tampering |

---

## Architecture

```
Incoming Traffic
      ↓
[L1] Netlink socket — link state monitoring
[L2] AF_PACKET ETH_P_ARP — ARP reply inspection
[L3] AF_PACKET ETH_P_IP — IP reputation filtering
[L4] Raw TCP — port scan detection + RST injection
[L5] Raw TCP — SYN flood detection
[L6] Raw TCP — TLS ClientHello policy engine
[L7] UDP port 53 — DNS denylisting
[L7] TCP port 8080 — HTTP proxy + blocklist
      ↓
common/enforce.c — shared iptables PI_BLOCKER chain
common/reputation.c — IP threat intel feeds
common/blocklist.c — domain blocklist (70k+ entries)
```

Every layer is independently threaded. Every decision is logged with inline MITRE technique tags:
```
[2026-03-06 15:39:21] [LAYER_4] [PORT] [BLOCKED] src=10.0.0.131 dst_port=587 unique_ports=18 d3fend=D3-NTCD attck=T1046
[2026-03-06 15:39:21] [LAYER_7] [DNS] [BLOCKED] domain=doubleclick.net client=10.0.0.5 d3fend=D3-DNSDL attck=T1071.004
[2026-03-06 15:39:21] [LAYER_6] [TLS] [BLOCKED (deprecated TLS)] host=example.com tls_ver=0x0301 d3fend=D3-TLSIC attck=T1573
```

---

## Quick Start

```bash
git clone https://github.com/micccon/pi-blocker-c.git
cd pi-blocker

# Build all layers
make

# Run all layers at once (requires root)
sudo ./start_layer_all.sh
```

That's it. The startup script launches all 8 processes (DNS, HTTP proxy, TLS inspector, session tracker, port filter, IP filter, ARP monitor, link monitor) and initializes the shared PI_BLOCKER iptables chain.

**Run individual layers manually:**
```bash
sudo ./layer_7/start_layer7.sh    # DNS + HTTP proxy
sudo ./layer_6/start_layer6.sh    # TLS inspector
sudo ./layer_5/start_layer_5.sh   # Session tracker
sudo ./layer_4/start_layer4.sh    # Port filter
sudo ./layer_3/start_layer3.sh    # IP filter
sudo ./layer_2/start_layer2.sh    # ARP monitor
sudo ./layer_1/start_layer1.sh    # Link monitor
```

**Run tests:**
```bash
cd layer_tests
sudo ./run_all.sh                 # Run all layer tests
sudo ./layer_4_test.sh            # Run individual layer test
```

---

## Project Structure

```
pi-blocker/
├── Makefile                        — builds all layers
├── start_layer_all.sh              — launches all layers at once
├── README.md
├── D3FEND.md                       — D3FEND technique mapping per layer
├── ATT&CK.md                       — ATT&CK attack simulation writeup
├── common/
│   ├── enforce.c / enforce.h       — shared iptables enforcement (PI_BLOCKER chain)
│   ├── reputation.c / reputation.h — IP threat intel feed loading + CIDR matching
│   ├── blocklist.c / blocklist.h   — domain blocklist + binary search
│   └── net_hdrs.h                  — packed protocol headers (IP, TCP, UDP, DNS, TLS, ARP)
├── layer_7/
│   ├── dns/                        — DNS sinkhole (D3-DNSDL)
│   │   ├── dns.c / dns.h
│   │   ├── main.c
│   │   └── Makefile
│   ├── http/                       — HTTP proxy + CONNECT handler (D3-HTTPA)
│   │   ├── proxy.c / proxy.h
│   │   ├── main.c
│   │   └── Makefile
│   ├── start_layer7.sh
│   ├── Makefile
│   └── layer_7.md
├── layer_6/                        — TLS ClientHello policy engine (D3-TLSIC)
│   ├── tls_inspector.c / tls_inspector.h
│   ├── main.c
│   ├── start_layer6.sh
│   ├── Makefile
│   └── layer_6.md
├── layer_5/                        — SYN flood detection (D3-CSLL)
│   ├── session.c / session.h
│   ├── main.c
│   ├── start_layer_5.sh
│   ├── Makefile
│   └── layer_5.md
├── layer_4/                        — Port scan detection + RST injection (D3-NTCD)
│   ├── filter.c / filter.h
│   ├── main.c
│   ├── start_layer4.sh
│   └── Makefile
├── layer_3/                        — IP reputation filtering (D3-ITF)
│   ├── ip_filter.c / ip_filter.h
│   ├── main.c
│   ├── start_layer3.sh
│   ├── Makefile
│   └── layer_3.md
├── layer_2/                        — ARP spoofing detection (D3-AAF)
│   ├── arp_monitor.c / arp_monitor.h
│   ├── main.c
│   ├── start_layer2.sh
│   ├── Makefile
│   └── layer_2.md
├── layer_1/                        — Physical link state monitoring (D3-NTA)
│   ├── link_monitor.c / link_monitor.h
│   ├── main.c
│   ├── start_layer1.sh
│   └── Makefile
├── layer_tests/
│   ├── run_all.sh
│   ├── layer_1_test.sh through layer_7_test.sh
├── reputation/
│   └── reputation.txt              — combined Feodo Tracker + Emerging Threats feed
├── hostnames/
│   ├── blocklist.txt               — 70k+ ad + malicious domains (sorted)
│   ├── random-domains-dnsperf.txt  — benchmark dataset
│   └── random_domains.txt
└── images/
```

---

## Layer Details

### Layer 7 — DNS Blocker (D3-DNSDL)
- Raw UDP socket on port 53
- 70,000+ domain blocklist, binary search O(log n)
- RFC 1035 compliant parsing — pointer-based name decompression
- Subdomain matching — blocking `evil.com` blocks `sub.evil.com`
- Returns REFUSED for blocked domains
- Counters: T1071.004

**Performance on Pi Zero 2 W:**
```
Queries/sec:     747.59
Avg latency:     79.7ms
Memory:          ~15MB with 70k domains
```

### Layer 7 — HTTP Proxy (D3-HTTPA)
- TCP socket on port 8080, pthread per connection
- Parses Host header, checks against blocklist
- Returns 403 Forbidden for blocked domains
- CONNECT tunneling for HTTPS — **with destination validation** (loopback + RFC 1918 blocked)
- Counters: T1071.001

### Layer 6 — TLS Inspector (D3-TLSIC)
- Raw socket monitors ports 443 and 8080
- Inspects TLS ClientHello before handshake completes
- Policy checks: TLS version (min 1.2), SNI presence, ALPN value, extension count, ClientHello size
- TCP RST injection on policy violation
- Counters: T1573

### Layer 5 — Session Tracker (D3-CSLL)
- Tracks SYN packets per source IP in tumbling 60s window
- Hash table (1021 buckets, prime, chaining) — O(1) lookup
- Threshold: 20 SYNs → block via iptables
- Mutex-protected, thread-safe
- Counters: T1499

### Layer 4 — Port Filter (D3-NTCD)
- Detects SYN, NULL, XMAS, FIN scan types by TCP flag inspection
- Circular buffer tracks unique destination ports per source IP in 10s window
- Threshold: 16 unique ports → block + RST inject
- Counters: T1046

### Layer 3 — IP Filter (D3-ITF)
- AF_PACKET raw socket — sees forwarded traffic
- Loads Feodo Tracker (botnet C2) + Emerging Threats feeds
- CIDR + single IP matching, up to 4096 entries
- Auto-updated via `reputation/update.sh`
- Counters: T1590

### Layer 2 — ARP Monitor (D3-AAF)
- AF_PACKET ETH_P_ARP socket, monitors ARP replies only
- Maintains IP→MAC table with 300s stale entry pruning
- Alerts when MAC changes for known IP
- Counters: T1557.002

### Layer 1 — Link Monitor (D3-NTA)
- AF_NETLINK NETLINK_ROUTE socket, RTMGRP_LINK group
- Detects carrier loss (IFF_RUNNING drops)
- Tracks flap count per interface with 10s alert cooldown
- Counters: T1200

---

## Shared Infrastructure

**`common/enforce.c`** — All layers use a single enforcement library:
- Dedicated `PI_BLOCKER` iptables chain — clean flush on exit
- `block_ip()`, `block_port()`, `block_proto()` — deduplicated via hash tables
- `rst_inject()` — TCP RST with RFC 793 pseudo-header checksum
- `pthread_once` init, mutex-protected throughout

**`common/net_hdrs.h`** — Packed protocol headers for zero-copy parsing:
- `struct ip_hdr`, `struct tcp_hdr`, `struct udp_hdr`
- `struct dns_hdr`, `struct tls_record_hdr`, `struct tls_handshake_hdr`
- `struct eth_hdr`, `struct arp_pkt`

---

## Attack Simulation

After building the stack, I attacked it using Kali Linux, Metasploit, Burp Suite, and nmap — treating the Pi as a black-box target.

**What the stack caught:**

| Attack | Tool | Layer | Result |
|---|---|---|---|
| Port scan | nmap -sV | L4 | Blocked after 16th unique port |
| SYN flood | hping3 --flood | L5 | Blocked after SYN threshold |
| ARP spoofing | arpspoof | L2 | Alerted immediately |
| IP reputation | hping3 -a \<bad-ip\> | L3 | Blocked before connection |
| DNS C2 | dig @pi evil.com | L7 | REFUSED |

**What the stack missed:**

A slow nmap scan (`--scan-delay 15s`) bypassed Layer 4's 10s detection window, revealing:
- Port 22: OpenSSH 10.0p2
- Port 8080: Open HTTP proxy

The HTTP proxy accepted `CONNECT 127.0.0.1:22` without destination validation — tunneling directly to SSH on localhost. This SSRF vulnerability allowed routing Metasploit's `ssh_login` module through the proxy, brute forcing credentials with a targeted Raspberry Pi default credential list, and obtaining a full interactive shell via proxychains — all without a single log entry across all 7 layers.

**Fix applied:** CONNECT destination validation — loopback and RFC 1918 ranges are now blocked before tunneling.

Full writeup: [`ATT&CK.md`](ATT&CK.md)  
D3FEND mapping: [`D3FEND.md`](D3FEND.md)

---

## Known Limitations

| Layer | Limitation | Planned Fix |
|---|---|---|
| L7 | HTTP/1.0 CONNECT without Host header required parser fix | Fixed |
| L6 | Packet-based TLS inspection only — fragmented ClientHello bypasses | TCP stream reassembly |
| L5 | Per-IP SYN threshold — distributed floods bypass | Subnet-level aggregate tracking |
| L4 | Fixed 10s window — slow scans bypass | Adaptive/cumulative scoring |
| L3 | Linear reputation scan O(n) | Binary search |

---

## Update Threat Intel Feeds

```bash
# Pull fresh Feodo Tracker + Emerging Threats feeds
cd reputation
chmod +x update.sh
sudo ./update.sh

# Update domain blocklist
curl -o hosts.txt https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
grep "^0.0.0.0" hosts.txt | awk '{print $2}' | grep -v "^0.0.0.0$" | grep -v "^localhost$" \
  > hostnames/blocklist.txt
sort -u hostnames/blocklist.txt -o hostnames/blocklist.txt
```

---

## Requirements

- Raspberry Pi Zero 2 W (or any Linux system)
- Root access (raw sockets require `CAP_NET_RAW`)
- `iptables` installed
- GCC + POSIX threads (`-lpthread`)
- Build: `make` in any layer directory or root

---

## Acknowledgments

- Domain blocklist: [Steven Black's unified hosts](https://github.com/StevenBlack/hosts)
- Threat intel: [Feodo Tracker](https://feodotracker.abuse.ch) — [Emerging Threats](https://rules.emergingthreats.net)
- MITRE D3FEND: [d3fend.mitre.org](https://d3fend.mitre.org)
- MITRE ATT&CK: [attack.mitre.org](https://attack.mitre.org)

---

**License:** MIT