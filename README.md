# Pi-Blocker 🛡️

A lightweight DNS sinkhole written in C that blocks ads and tracking domains at the network level. Designed to run efficiently on a Raspberry Pi, protecting all devices on your local network.

## Overview

Pi-Blocker intercepts DNS queries from devices on your network, checks them against a blocklist of 70,000+ known advertising and tracking domains, and either forwards legitimate requests to an upstream DNS server or refuses blocked ones. This approach provides network-wide ad blocking without requiring software installation on individual devices.

## Features

- **Network-wide blocking**: Protects all devices connected to your network
- **High-performance filtering**: Uses binary search on a sorted blocklist for O(log n) lookup speed
- **Subdomain matching**: Blocks `ads.example.com` when `example.com` is on the blocklist
- **DNS compression support**: Properly handles compressed DNS names (RFC 1035)
- **Configurable upstream DNS**: Forward to any DNS server (defaults to Google's 8.8.8.8)
- **Minimal resource usage**: Optimized for Raspberry Pi hardware
- **Real-time logging**: See blocked and forwarded queries as they happen

## How It Works

1. **Receives** DNS queries from clients on your network (port 53)
2. **Parses** the domain name from the DNS packet
3. **Checks** if the domain matches the blocklist using binary search
4. **Blocks** malicious queries by responding with DNS REFUSED (RCODE 5)
5. **Forwards** legitimate queries to an upstream DNS server
6. **Returns** the upstream response back to the client

## Installation

### Prerequisites

- Raspberry Pi (any model) or Linux system
- GCC compiler
- Root/sudo access (required to bind to port 53)

### Build

```bash
# Clone the repository
git clone https://github.com/yourusername/pi-blocker.git
cd pi-blocker

# Compile
make

# Run (requires sudo for port 53)
sudo ./pi-blocker
```

## Usage

### Basic Usage

```bash
# Use default upstream DNS (8.8.8.8)
sudo ./pi-blocker

# Specify custom upstream DNS server
sudo ./pi-blocker 1.1.1.1
```

### Configure Your Devices

**Option 1: Network-wide (Recommended)**

Configure your router's DHCP settings to use your Raspberry Pi's IP address as the primary DNS server. This protects all devices automatically. Consult your router's documentation for specific steps.

**Option 2: Individual Device (Windows)**

1. Open **Settings** → **Network & Internet**
2. Click on your connection (Wi-Fi or Ethernet)
3. Click **Edit** next to DNS server assignment
4. Select **Manual**
5. Toggle **IPv4** to **On**
6. Enter your Raspberry Pi's IP address as **Preferred DNS**
7. Click **Save**

**Option 3: Individual Device (macOS/Linux)**

Similar process through Network Settings, or edit `/etc/resolv.conf` to point to your Pi's IP.

### Test It Out

```bash
# Test blocking (should fail or return refused)
nslookup ads.example.com YOUR_PI_IP

# Test allowed domain (should succeed)
nslookup google.com YOUR_PI_IP
```

## Project Structure

```
pi-blocker/
├── main.c              # Server loop, socket handling, request forwarding
├── dns.c               # DNS parsing, blocklist management
├── dns.h               # Constants, structures, function declarations
├── Makefile            # Build configuration
└── hostnames/
    └── blocklist.txt   # 70,000+ blocked domains (one per line, sorted)
    └── random_domains.txt # List of 10k domains for benchmarking
```

## Technical Highlights

### DNS Packet Parsing
- Implements RFC 1035 DNS message format parsing
- Handles DNS name compression (pointer following with jump protection)
- Supports standard label encoding
- Buffer overflow protection and malformed packet handling

### Efficient Blocklist Searching
- Binary search algorithm for O(log n) lookups
- Hierarchical domain matching (blocks all subdomains)
- In-memory storage for fast access
- Pre-sorted blocklist for optimal performance

### Network Architecture
- UDP socket programming with dual-socket design
- Non-blocking upstream queries with timeout protection
- Proper network byte order handling (ntohs/htons)
- Poll-based timeout mechanism to prevent server hangs

## Configuration

### Blocklist

The blocklist is located in `hostnames/blocklist.txt` and uses domains from [Steven Black's unified hosts file](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts).

To update your blocklist:

```bash
# Download the latest hosts file
curl -o hosts.txt https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts

# Extract domains (skip IP mappings, comments, and localhost)
grep "^0.0.0.0" hosts.txt | awk '{print $2}' | grep -v "^0.0.0.0$" | grep -v "^localhost$" > hostnames/blocklist.txt

# Sort alphabetically (required for binary search)
sort -u hostnames/blocklist.txt -o hostnames/blocklist.txt
```

Format (one domain per line):
```
ads.example.com
tracker.another-site.com
analytics.website.org
```

**Important**: The blocklist must be sorted alphabetically for binary search to work.

### Customization

Key constants in `dns.h`:

- `DNS_BUFFER_SIZE`: Buffer for client queries (512 bytes)
- `UPSTREAM_BUFFER_SIZE`: Buffer for upstream responses (65536 bytes)
- `DNS_NAME_SIZE`: Maximum domain name length (256 bytes)

## Performance

On a Raspberry Pi 4:
- ~0.1ms lookup time per query
- Handles hundreds of queries per second
- Minimal memory footprint (~10-15 MB with full blocklist)
- Near-zero CPU usage when idle

## Limitations

- IPv4 only (no IPv6 support currently)
- UDP only (no DNS-over-HTTPS/TLS)
- Single-threaded (handles one query at a time)
- No caching mechanism

## Future Improvements

- [ ] Add DNS query caching to reduce upstream requests
- [ ] Implement IPv6 support
- [ ] Multi-threading for concurrent query handling
- [ ] Web interface for statistics and management
- [ ] Whitelist support for overriding blocks
- [ ] Custom block page redirect option

## Troubleshooting

**Permission denied on port 53:**
```bash
sudo ./pi-blocker  # Must run as root
```

**No domains being blocked:**
- Verify blocklist exists at `hostnames/blocklist.txt`
- Ensure blocklist is sorted alphabetically
- Check that domains are lowercase in the file

**Queries timing out:**
- Check upstream DNS server is reachable
- Verify no firewall is blocking outbound UDP port 53
- Try a different upstream DNS server

## License

This project is open source and available under the MIT License.

## Acknowledgments

- Blocklist from [Steven Black's unified hosts file](https://github.com/StevenBlack/hosts) - a consolidated collection of reputable host files
- Inspired by Pi-hole and other DNS sinkhole projects
- Built as a portfolio project to demonstrate C networking and systems programming

---

**Note**: This is an educational project. For production use, consider established solutions like Pi-hole which offer additional features, web interfaces, and community support.