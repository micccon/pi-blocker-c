# Pi-Blocker 🛡️

A high-performance, multi-threaded DNS sinkhole written in C that blocks ads and tracking domains at the network level. Runs efficiently on a Raspberry Pi Zero 2 W, protecting all devices on your local network.

## Visual Results
| Before Pi-Blocker | After Pi-Blocker |
|-------------------|------------------|
| ![Without blocking](images/without-pi-blocker.png) | ![With blocking](images/with-pi-blocker.png) |

*Network-wide ad blocking - no software installation required on individual devices*

## Features

- **Multi-threaded**: POSIX threads handle concurrent queries without blocking
- **Fast lookups**: Binary search on 70k+ domains (O(log n) performance)
- **DNS compression**: RFC 1035 compliant packet parsing with pointer following
- **Subdomain matching**: Blocks `ads.example.com` when `example.com` is listed
- **Real-time logging**: Monitor blocked/forwarded queries as they happen

## Performance (Raspberry Pi Zero 2 W)

Tested with `dnsperf` - 100 concurrent connections, 30 seconds:

```
Queries per second:   747.59
Queries completed:    23,072 (98.97%)
Average Latency:      79.7ms (min 0.35ms)
Memory usage:         ~15MB with 70k domains
```

## Quick Start

```bash
# Clone and build
git clone https://github.com/yourusername/pi-blocker.git
cd pi-blocker
make

# Run (default upstream: 8.8.8.8)
sudo ./pi-blocker

# Or specify custom upstream DNS
sudo ./pi-blocker 1.1.1.1
```

## Setup

**Configure DNS on Windows:**
1. **Settings** → **Network & Internet** → Click connection
2. **Edit DNS** → **Manual** → **IPv4 On**
3. Enter Pi's IP as **Preferred DNS** → **Save**

**Other systems**: Update DNS in network settings or edit `/etc/resolv.conf`

**Test**: `nslookup google.com YOUR_PI_IP` or browse the web normally

## How It Works

```
Client Query → Spawn Thread → Parse Domain → Check Blocklist
                                                ↓
                                         Blocked? → Send REFUSED
                                                ↓
                                         Forward → Upstream DNS → Return Response
```

Each query runs in its own thread with a thread-local socket, preventing head-of-line blocking.

## Architecture Highlights

**Multi-threading**
- Worker thread per query using `pthread_create()` and `pthread_detach()`
- Thread-local upstream sockets eliminate race conditions
- No mutexes needed - blocklist is read-only after load

**DNS Parsing**
- Handles label compression with jump protection (max 100 loops)
- Buffer overflow protection on name reads
- Case-insensitive domain matching

**Blocklist Engine**
- Binary search: O(log n) lookups in microseconds
- Hierarchical matching: blocks subdomains automatically
- 70k+ domains from [Steven Black's unified hosts](https://github.com/StevenBlack/hosts)

## Project Structure

```
pi-blocker/
├── main.c          # Socket setup, thread spawning
├── dns.c           # Parsing, blocklist, request handling
├── dns.h           # Structs and constants
├── Makefile
├── hostnames/
    ├── blocklist.txt              # 70k+ domains (sorted)
    ├── random-domains.txt         # List of 10k domains
    └── random-domains-dnsperf.txt # Benchmark dataset
└── images/
    ├── with-pi-blocker.png
    └── without-pi-blocker.png
```

## Configuration

**Update Blocklist:**
```bash
curl -o hosts.txt https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
grep "^0.0.0.0" hosts.txt | awk '{print $2}' | grep -v "^0.0.0.0$" | grep -v "^localhost$" > hostnames/blocklist.txt
sort -u hostnames/blocklist.txt -o hostnames/blocklist.txt
```

**Benchmark:**
```bash
sudo apt-get install dnsperf
dnsperf -s YOUR_PI_IP -l 30 -Q 1000 -n 100 -d hostnames/random-domains-dnsperf.txt
```

## Technical Deep Dive

### Thread Safety Strategy

**The Challenge**: Multiple threads accessing shared resources (blocklist, sockets) simultaneously.

**The Solution**:
- **Read-only blocklist**: Loaded once at startup, never modified → safe for concurrent reads without locks
- **Thread-local upstream sockets**: Each worker thread creates its own socket → eliminates contention
- **Independent task structs**: Each thread receives a private `dns_task_t` with query data
- **No shared mutable state**: Zero mutexes or atomic operations needed

### Memory Management

**Query Lifecycle**:
1. Main thread allocates `dns_task_t` with `calloc()` and copies query data
2. Worker thread spawned and detached with `pthread_detach()`
3. Thread parses domain (returns malloc'd string) and processes query
4. Thread frees domain string and task struct before exit
5. OS reclaims thread resources automatically

**Blocklist**: Array of 70k+ string pointers (~15MB total), loaded once at startup, freed on shutdown.

### DNS Packet Parsing

DNS packets use **pointer compression** (RFC 1035) to reduce size:
- **Labels**: `3www6google3com0` (length-prefixed segments)
- **Pointers**: `0xC00C` (jump to offset 12 in packet)

**Safety mechanisms**:
```c
// Detect pointer: top 2 bits = 11
if ((*reader & 0xC0) == 0xC0) {
    int offset = ((*reader & 0x3F) << 8) | *(reader + 1);
    reader = buffer + offset;
}
```
- `MAX_LOOP_COUNT` (100) prevents infinite loops from malicious packets
- Buffer overflow checks before every memory operation

### Blocklist Search Algorithm

**Binary Search**: O(log n) lookups via `bsearch()` - 70k domains checked in ~16 comparisons

**Hierarchical Matching**: Walks up domain tree checking each level
```
ads.doubleclick.net → check "ads.doubleclick.net"
                    → check "doubleclick.net" (BLOCKED!)
```

### Network Architecture

**Dual Socket Design**:
- **Client socket**: Bound to port 53, shared (read-only) for `sendto()` responses
- **Upstream sockets**: Each thread creates its own for upstream queries

**Why separate upstream sockets?** Prevents threads from stealing each other's responses on `recvfrom()`.

**Timeout Protection**: Uses `poll()` with 2-second timeout to avoid blocking on dead upstream servers.

### Error Handling

**Fail gracefully** - bad input never crashes the server:
- Malformed packets (<12 bytes): Silently dropped
- Thread creation failures: Logged, server continues
- Upstream timeouts: No response sent to client
- Memory allocation failures: Query skipped, resources freed

### Performance Optimizations

1. **Pre-sorted blocklist**: Avoids O(n log n) sort at startup
2. **Binary search**: O(log n) vs O(n) linear scan
3. **In-memory storage**: No disk I/O during queries
4. **Thread-per-query**: Simple model, sufficient for <1000 QPS
5. **Minimal copying**: Pass pointers, copy only when necessary

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Permission denied | `sudo ./pi-blocker` (port 53 requires root) |
| Nothing blocked | Verify `hostnames/blocklist.txt` exists and is sorted |
| Queries timeout | Check upstream reachable: `ping 8.8.8.8` |
| High memory | Expected (~15MB with 70k domains) |

## Future Enhancements

- DNS caching (Redis/LRU)
- IPv6 support
- DNS-over-HTTPS/TLS
- Web dashboard with statistics
- Whitelist support
- Docker containerization

## Acknowledgments

- Blocklist: [Steven Black's unified hosts](https://github.com/StevenBlack/hosts)
- Test domains: [OpenDNS public lists](https://github.com/opendns/public-domain-lists)
- Inspired by Pi-hole

Built as a portfolio project demonstrating C systems programming, multi-threading, network protocols, and performance optimization.

---

**License**: MIT | **Note**: Educational project - for production use, consider [Pi-hole](https://pi-hole.net/)