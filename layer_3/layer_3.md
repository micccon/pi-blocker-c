# Layer 3 — Network Layer

## OSI Context
The Network Layer handles logical addressing and routing — it is where IP addresses live. In network security this is the earliest point at which you can inspect and filter traffic based on source identity. Blocking at Layer 3 is the most efficient defense because malicious packets are dropped before any upper layer processing occurs.

---

## D3FEND Technique

- **ID**: D3-ITF
- **Name**: IP Traffic Filtering
- **Tactic**: Isolate
- **Status**: ✅ Implemented
- **Definition**: Filtering inbound IP traffic based on the reputation of the source address, dropping packets from known malicious hosts before they reach application layer processing.

---

## Digital Artifact
IPv4 source address — 32-bit field at byte offset 12 in the IP header. RFC 791 section 3.1. Every packet carries this field and it cannot be omitted, making it a reliable filter point even before transport or application layer headers are parsed.

---

## ATT&CK Mapping
- **Technique ID**: T1590
- **Technique Name**: Gather Victim Network Information
- **Why**: Adversaries probe and scan networks before launching attacks. Known scanning infrastructure, botnet C2 servers, and compromised hosts appear in threat intelligence feeds. Blocking them at the IP layer prevents reconnaissance and stops known attack infrastructure from reaching any service.

---

## Threat Intelligence Sources
| Feed | URL | Content |
|---|---|---|
| Emerging Threats | rules.emergingthreats.net/blockrules/compromised-ips.txt | Botnet and malware C2 IPs |
| Feodo Tracker | feodotracker.abuse.ch/downloads/ipblocklist.txt | Active botnet C2 servers |
| Spamhaus DROP | spamhaus.org/drop/drop.txt | Hijacked netblocks (CIDR) |

Feeds are combined and deduplicated at startup via `reputation/update.sh`.

---

## What This Implementation Does
On startup, loads a reputation file containing known malicious IPs and CIDR ranges into a sorted array. Opens a raw IP socket and captures all inbound packets. For each packet, extracts the source IP and checks it against the reputation list using CIDR matching. If a match is found, `block_ip()` adds an iptables DROP rule and the event is logged. Loopback traffic is filtered out to prevent the Pi from blocking itself.

---

## Architecture

```
Raw IP packet arrives
         ↓
  Raw socket captures (SOCK_RAW, IPPROTO_IP)
         ↓
  Validate IP header (version == 4, IHL >= 20)
         ↓
  Filter: src_ip == loopback? → discard
         ↓
  Spawn thread → handle_ip_packet()
         ↓
  check_ip_reputation(src_ip)
    → reputation_match_ip()
    → linear scan with cidr_match() per entry
    → return 1 if match, 0 if clean
         ↓
  match  → block_ip() → log BLOCKED
  clean  → log ALLOWED
```

---

## Reputation Module

Reputation logic is isolated in `common/reputation.c` so other layers can reuse it. The module maintains a global sorted array of `reputation_entry_t` structs, each holding a network address in host byte order and a prefix length.

Single IPs are stored as /32 entries. All entries are sorted by network address after loading using `qsort()` for future binary search optimization.

**CIDR matching:**
```c
uint32_t mask = (prefix == 0) ? 0 : (~0u << (32 - prefix));
return (src_hbo & mask) == (network_hbo & mask);
```

The prefix == 0 special case exists because `<< 32` on a 32-bit integer is undefined behavior in C.

**Complexity:** O(n) per packet — linear scan across all entries. For interview: mention a production system would use a radix trie (like the Linux FIB) for O(k) lookup where k = prefix length.

---

## Files
- `layer_3/main.c` — startup, loads reputation, signal handler, calls `start_ip_filter()`
- `layer_3/ip_filter.c` — raw socket capture, thread spawning, logging
- `layer_3/ip_filter.h` — structs, constants, function signatures
- `common/reputation.c` — CIDR parsing, matching, cleanup
- `common/reputation.h` — reputation entry struct, function signatures
- `reputation/update.sh` — downloads and merges threat intel feeds
- `reputation/reputation.txt` — combined feed loaded at startup

---

## How to Run
```bash
# update threat intel feeds first
cd reputation && bash update.sh

cd layer_3
make
sudo ./ip-filter                        # uses default reputation.txt
sudo ./ip-filter ../reputation/reputation.txt  # specify path
```

---

## Example Log Output
```
[2025-01-07 23:45:10] [LAYER_3] [IP_REP] [ALLOWED] src=192.168.1.5 d3fend=D3-ITF attck=T1590
[2025-01-07 23:45:11] [LAYER_3] [IP_REP] [BLOCKED] src=185.220.101.4 d3fend=D3-ITF attck=T1590
```

---

## Limitations
- Linear scan is O(n) — acceptable for 4096 entries, not for millions
- Reputation feeds must be manually updated — stale feeds miss new threats
- Source IP spoofing bypasses reputation filtering entirely
- Does not catch attacks from clean IPs not yet in any feed

---

## Phase 2 — Planned Attack
- **Tool**: Custom Python script, hping3
- **Method**: Send packets spoofing a known malicious IP from the reputation list. Then send from a clean IP that is not in any feed.
- **Expected Result**: Spoofed malicious IP caught and blocked. Clean IP passes through — demonstrating that reputation filtering only catches known threats and why Layers 4 and 5 are needed for behavioral detection.