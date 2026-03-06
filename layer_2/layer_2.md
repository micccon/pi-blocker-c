# Layer 2 — Data Link Layer

## OSI Context
The Data Link Layer handles physical addressing and frame delivery between devices on the same network segment. It is where MAC addresses live — below IP, below TCP, below everything else. Security at this layer catches attacks that are invisible to upper layers because they never generate IP traffic.

---

## D3FEND Technique

- **ID**: D3-AAF
- **Name**: ARP Cache Poisoning Detection
- **Tactic**: Detect
- **Status**: ✅ Implemented
- **Definition**: Monitoring ARP reply traffic to detect inconsistencies between IP addresses and their associated MAC addresses, identifying attempts to poison ARP caches and intercept network traffic.

---

## Digital Artifact
ARP reply packet — EtherType 0x0806, operation code 2. RFC 826. Contains sender hardware address (SHA) and sender protocol address (SPA) — the MAC and IP the sender is claiming to own. This is the packet used to poison ARP caches.

---

## ATT&CK Mapping
- **Technique ID**: T1557.002
- **Technique Name**: ARP Cache Poisoning
- **Why**: Adversaries send gratuitous ARP replies to overwrite legitimate IP→MAC mappings in cache tables. This redirects traffic through the attacker enabling man-in-the-middle interception of credentials, session tokens, and plaintext data.

---

## What This Implementation Does
Opens an `AF_PACKET` raw socket bound to `ETH_P_ARP` to capture all ARP frames on the interface. Filters for ARP replies only (oper == 2), and further filters for IPv4 over Ethernet (htype == 1, ptype == 0x0800, hlen == 6, plen == 4). For each reply, extracts the sender IP and MAC and checks them against a ground-truth ARP table. If the IP is already known with a different MAC, a spoof alert is logged. If the IP is new, the mapping is learned and logged. Stale entries are pruned automatically when the table fills.

---

## Architecture

```
Raw Ethernet frame arrives
         ↓
  AF_PACKET socket captures (ETH_P_ARP)
         ↓
  Validate length >= eth_hdr + arp_pkt
         ↓
  Filter: ethertype == 0x0806 (ARP)?
    NO  → discard
         ↓
  Filter: oper == 2 (reply)?
    NO  → discard (requests are harmless)
         ↓
  Filter: IPv4 over Ethernet?
    NO  → discard
         ↓
  Spawn thread → handle_arp_packet()
         ↓
  Extract sender_ip (spa) and sender_mac (sha)
         ↓
  check_arp_spoof()
    → lock mutex
    → arp_lookup() — find existing entry for this IP
    → MAC changed?  → save old_mac, update entry → return 1 (spoof)
    → same MAC?     → update last_seen              → return 0 (ok)
    → new IP?       → arp_insert()                  → return 0 (learned)
    → table full?   →                                 return -1 (error)
    → unlock mutex
         ↓
  return 1  → log ALERT (old_mac vs new_mac)
  return 0  → log OK or LEARNED
  return -1 → log ERROR
```

---

## ARP Table Design

Hash table mapping IP addresses to known MAC addresses. Same chaining pattern as Layers 4 and 5. Each entry stores the MAC last seen for that IP and a timestamp.

**Stale entry pruning:** When the table reaches `ARP_ENTRY_MAX`, stale entries older than `ARP_STALE_SECONDS` are pruned before failing the insert. This prevents the table from filling on busy networks with many short-lived devices.

**Why only ARP replies:** ARP requests are broadcasts asking "who has X?" — they are harmless and expected. ARP replies are where poisoning happens because they contain the IP→MAC claim that gets written into cache tables.

---

## old_mac Output Parameter

`check_arp_spoof()` takes an `old_mac_out[6]` parameter. When a spoof is detected the old known MAC is copied into this buffer before the entry is updated. This lets `log_arp_decision()` show both the legitimate MAC and the attacker's MAC in the alert:

```
old_mac=aa:bb:cc:dd:ee:ff  ← legitimate device
mac=11:22:33:44:55:66      ← attacker claiming that IP
```

---

## Files
- `layer_2/main.c` — startup, signal handler, calls `start_arp_monitor()`
- `layer_2/arp_monitor.c` — ARP table, spoof detection, logging
- `layer_2/arp_monitor.h` — structs, constants, function signatures

---

## Constants
| Constant | Value | Meaning |
|---|---|---|
| ARP_TABLE_SIZE | 256 | Hash buckets |
| ARP_ENTRY_MAX | 1024 | Max tracked IP→MAC mappings |
| ARP_BUFFER_SIZE | 1518 | Max Ethernet frame size |
| ARP_STALE_SECONDS | 300 | Seconds before entry considered stale |

---

## How to Run
```bash
cd layer_2
make
sudo ./arp-monitor

# Test ARP spoofing from another machine:
sudo apt install arpspoof
sudo arpspoof -i eth0 -t <victim_ip> <gateway_ip>
# → should show ALERT with old_mac vs new_mac
```

---

## Example Log Output
```
[2025-01-07 23:45:10] [LAYER_2] [ARP] [OK]    ip=192.168.1.1  mac=aa:bb:cc:dd:ee:ff old_mac=N/A          d3fend=D3-AAF attck=T1557.002
[2025-01-07 23:45:11] [LAYER_2] [ARP] [ALERT] ip=192.168.1.1  mac=11:22:33:44:55:66 old_mac=aa:bb:cc:dd:ee:ff d3fend=D3-AAF attck=T1557.002
```

---

## Limitations
- Detection only — no active response at this layer. ARP has no authentication mechanism so there is no reliable way to block a spoof without also implementing 802.1X port authentication or static ARP entries.
- First ARP reply for any IP is always trusted — an attacker who poisons the cache before this monitor sees the legitimate mapping will not be detected.
- Gratuitous ARP from legitimate devices (IP renewal, failover) will trigger false positives.

---

## Phase 2 — Planned Attack
- **Tool**: `arpspoof`, Bettercap
- **Method**: Send gratuitous ARP replies claiming the gateway IP belongs to the attacker's MAC. Then attempt to intercept HTTP traffic between a victim and the gateway.
- **Expected Result**: ALERT logged immediately when MAC changes for a known IP. Demonstrates that ARP poisoning is detected at Layer 2 before any upper layer sees the intercepted traffic.