# Layer 5 — Session Layer

## OSI Context
The Session Layer manages the lifecycle of connections between applications — establishing, maintaining, and terminating sessions. In network security this is where connection rate limiting lives, detecting patterns in how connections are initiated rather than what data they carry.

---

## D3FEND Technique

- **ID**: D3-CSLL
- **Name**: Connection Attempt Limit
- **Tactic**: Isolate
- **Status**: ✅ Implemented
- **Definition**: Limiting the number of new connection attempts from a single source within a defined time window, detecting and responding to connection flooding before it exhausts server resources.

---

## Digital Artifact
TCP SYN packet — the first packet of every new TCP connection attempt. RFC 793 section 3.4. SYN flag = bit 1 of TCP flags byte (0x02). SYN+ACK (0x12) is filtered out — it's a server response, not an attack vector.

---

## ATT&CK Mapping
- **Technique ID**: T1499
- **Technique Name**: Endpoint Denial of Service
- **Why**: Adversaries flood targets with TCP SYN packets to exhaust connection state tables and prevent legitimate connections. Tracking SYN rates per source IP within a time window detects this before resources are exhausted.

---

## What This Implementation Does
Opens a raw TCP socket and captures all TCP packets. Filters for pure SYN packets only. Hashes the source IP into a session table where a per-IP SYN counter is maintained within a tumbling time window. If any IP exceeds `SESSION_SYN_THRESHOLD` SYNs within `SESSION_WINDOW_SECONDS` it is flagged, the enforcement hook fires, and the event is logged. Counters reset when the window expires. The table is mutex-protected for thread safety.

---

## Architecture
```
Raw TCP packet arrives
         ↓
  Raw socket captures (SOCK_RAW, IPPROTO_TCP)
         ↓
  Filter: protocol == TCP AND pure SYN (not SYN+ACK)
    NO  → discard
    YES → spawn thread
         ↓
  check_syn_flood()
    → lock mutex
    → lookup or insert src_ip in hash table
    → reset window if expired
    → syn_count++
    → compare to threshold
    → unlock mutex
    → return -count (flood) or +count (allowed)
         ↓
  count < 0  → BLOCKED → session_enforce_block() → log
  count >= 0 → ALLOWED → log
```

---

## Files
- `layer_5/main.c` — startup, calls `start_session_tracker()`
- `layer_5/session.c` — hash table, SYN tracking, flood detection, logging
- `layer_5/session.h` — structs, constants, function signatures

---

## Constants
| Constant | Value | Meaning |
|---|---|---|
| SESSION_TABLE_SIZE | 1021 | Hash buckets (prime) |
| SESSION_WINDOW_SECONDS | 60 | Counting window length |
| SESSION_SYN_THRESHOLD | 15 | Max SYNs before flood flag |
| SESSION_MAX_ENTRIES | 4096 | Max tracked IPs |
| SESSION_BUFFER_SIZE | 4096 | Raw packet buffer |

---

## How to Run
```bash
cd layer_5
make
sudo ./session-tracker

# SYN flood test from another machine:
hping3 -S -p 80 --flood <pi_ip>
# → BLOCKED after threshold exceeded
```

---

## Example Log Output
```
[2025-01-07 23:45:10] [LAYER_5] [SESSION] [ALLOWED] src=192.168.1.5 syn_count=3  d3fend=D3-CSLL attck=T1499
[2025-01-07 23:45:12] [LAYER_5] [SESSION] [BLOCKED] src=192.168.1.5 syn_count=16 d3fend=D3-CSLL attck=T1499
[2025-01-07 23:45:12] [LAYER_5] [ENFORCE] would block 192.168.1.5
```

---

## Limitations
- Tumbling window means a flood spanning a window boundary may not be caught until the second window
- Table stops inserting new IPs at SESSION_MAX_ENTRIES — treated as allowed to avoid false positives
- Spoofed source IPs can cause legitimate IPs to be falsely flagged
- Blocking handed off to Layer 4 enforcement hook — not yet wired

---

## Phase 2 — Planned Attack
- **Tool**: `hping3`, custom Python SYN flooder
- **Method**: Single-source SYN flood above threshold, then distributed flood across many IPs to stay under per-IP limit
- **Expected Result**: Single-source flood caught. Distributed flood bypasses Layer 5 — demonstrating need for Layer 3 and Layer 4 as complementary defenses