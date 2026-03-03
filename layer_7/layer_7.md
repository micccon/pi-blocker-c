# Layer 7 — Application Layer

## OSI Context
As described by Cloudflare, Layer 7 (the application layer) is "the top layer of the data processing that occurs just below the surface or behind the scenes of the software applications that users interact with." This layer provides the protocols and functionalities that front-end applications depend on to operate — including HTTP, DNS, SMTP, and APIs. It is the layer closest to the end user, and the one most directly targeted by modern cyber attacks because it handles human-readable, application-specific data.

---

## D3FEND Techniques

This layer implements two D3FEND defensive techniques.

---

### Technique 1 — DNS Denylisting

- **ID**: D3-DNSDL
- **Name**: DNS Denylisting
- **Tactic**: Harden
- **Status**: ✅ Implemented
- **Definition**: Blocking DNS queries for known malicious, unwanted, or ad-serving domains by maintaining a denylisting of domain names. When a client queries a denylisted domain, the server returns a REFUSED response instead of resolving the name, preventing the client from ever establishing a connection to that domain.

#### Digital Artifact
DNS Resource Record — specifically the queried domain name extracted from the DNS Question Section of an incoming UDP packet.

#### ATT&CK Mapping
- **Technique ID**: T1071.004
- **Technique Name**: Application Layer Protocol: DNS
- **Why**: Adversaries use DNS as a covert channel for command and control (C2) communication, exfiltration, and malware callbacks. Blocking known malicious domains at the DNS level prevents infected hosts from contacting attacker infrastructure entirely.

#### What This Implementation Does
On startup, the server loads a sorted list of 70,000+ known malicious and ad-serving domains into memory. For every incoming DNS query on UDP port 53, it extracts the queried domain name, performs a binary search against the blocklist, and checks all parent domains (subdomain matching). If a match is found, the server returns a REFUSED response code to the client immediately. If no match is found, the query is forwarded to an upstream DNS resolver (default: 8.8.8.8) and the response is relayed back to the client. Every decision is logged in real time.

#### Architecture
```
Client DNS Query (UDP port 53)
         ↓
  Extract domain name from DNS Question Section
         ↓
  Binary search against 70k+ domain blocklist
  + subdomain walk (ads.example.com → example.com)
         ↓
  Blocked?
    YES → Send REFUSED response to client
          Log: [BLOCKED] d3fend=D3-DNSDL attck=T1071.004
    NO  → Forward query to upstream DNS (8.8.8.8)
          Relay response back to client
          Log: [FORWARD] d3fend=D3-DNSDL
```

#### Files
- `dns/main.c` — Socket setup on UDP port 53, main accept loop, thread spawning
- `dns/dns.c` — Blocklist loading, DNS packet parsing, binary search, request handling, upstream forwarding
- `dns/dns.h` — Structs (`dns_hdr`, `dns_task_t`), constants, and function signatures

#### How to Run
```bash
cd layer_7/dns
make
sudo ./pi-blocker           # uses default upstream 8.8.8.8
sudo ./pi-blocker 1.1.1.1  # specify custom upstream
```

#### Example Log Output
```
[2025-01-07 22:14:33] [LAYER_7] [DNS] [BLOCKED]  domain=ads.doubleclick.net  client=192.168.1.5  d3fend=D3-DNSDL  attck=T1071.004
[2025-01-07 22:14:34] [LAYER_7] [DNS] [FORWARD]  domain=google.com           client=192.168.1.5  d3fend=D3-DNSDL
```

#### Phase 2 — Planned Attack
- **Tool**: `dig` / custom Python DNS client
- **Method**: Send DNS queries for known C2 domains from the blocklist, then attempt DNS tunneling by encoding data in subdomain labels (e.g. `data.exfil.attacker.com`)
- **Expected Result**: All blocklisted domains return REFUSED. Subdomain matching catches parent domain variants. DNS tunneling attempts to unlisted domains will forward — exposing a gap for Phase 3 improvement.

---

### Technique 2 — HTTP Traffic Analysis

- **ID**: D3-HTTPA
- **Name**: HTTP Traffic Analysis
- **Tactic**: Detect / Harden
- **Status**: 🔲 In Progress
- **Definition**: Intercepting and analyzing HTTP request and response traffic to identify malicious content, unauthorized access attempts, or policy violations. Inspection targets include the request method, Host header, URL path, and query parameters.

#### Digital Artifact
HTTP Request — specifically the request line (`METHOD PATH HTTP/VERSION`) and the `Host` header extracted from the raw TCP stream on port 8080.

#### ATT&CK Mapping
- **Technique ID**: T1071.001
- **Technique Name**: Application Layer Protocol: Web Protocols
- **Why**: Adversaries use HTTP to blend command and control traffic in with normal web browsing, making it difficult to detect without inspecting the application layer content. Malware callbacks, phishing redirects, and ad tracking all use HTTP as their transport.

#### What This Implementation Does
The HTTP proxy listens on TCP port 8080. When a client sends an HTTP request (configured via browser or system proxy settings), the proxy reads the full request from the TCP stream, parses the Host header and URL path, and checks the hostname against the same blocklist used by the DNS layer. If blocked, it returns a 403 Forbidden response. If allowed, it resolves the hostname, opens a new TCP connection to the real server, forwards the request, and relays the response back to the client. Every decision is logged with the D3FEND technique ID.

#### Architecture
```
Client HTTP Request (TCP port 8080)
         ↓
  Read TCP stream until \r\n\r\n (end of headers)
         ↓
  Parse: METHOD, Host header, URL path
         ↓
  Strip port from Host if present (e.g. host:8080 → host)
  Lowercase the hostname
         ↓
  Check hostname against blocklist (reuse dns is_blocked())
         ↓
  Blocked?
    YES → Send HTTP 403 Forbidden response to client
          Log: [BLOCKED] d3fend=D3-HTTPA attck=T1071.001
    NO  → Resolve hostname with getaddrinfo()
          Open TCP connection to real server port 80
          Forward raw request bytes
          Read response and relay to client
          Log: [FORWARD] d3fend=D3-HTTPA
         ↓
  Close all sockets, free memory
```

#### Files
- `http_proxy/main.c` — TCP socket setup on port 8080, accept loop, thread spawning
- `http_proxy/proxy.c` — Request reading, parsing, blocklist check, 403 response, forwarding
- `http_proxy/proxy.h` — `http_task_t` struct, constants, function signatures

#### How to Run
```bash
cd layer_7/http_proxy
make
sudo ./http-proxy

# Configure your browser or system to use Pi as HTTP proxy:
# Proxy host: YOUR_PI_IP
# Proxy port: 8080

# Test from another machine:
curl http://example.com --proxy http://YOUR_PI_IP:8080
curl http://doubleclick.net --proxy http://YOUR_PI_IP:8080  # should 403
```

#### Example Log Output
```
[2025-01-07 22:15:10] [LAYER_7] [HTTP] [BLOCKED]  host=ads.doubleclick.net  path=/track.js      client=192.168.1.5  d3fend=D3-HTTPA  attck=T1071.001
[2025-01-07 22:15:11] [LAYER_7] [HTTP] [FORWARD]  host=example.com          path=/index.html    client=192.168.1.5  d3fend=D3-HTTPA
```

#### Phase 2 — Planned Attack
- **Tool**: `curl`, custom Python script, Burp Suite
- **Method**: Send HTTP requests with malicious Host headers, attempt URL path traversal (`/../etc/passwd`), send requests to known C2 domains over HTTP, try HTTP header injection
- **Expected Result**: Blocklisted hosts return 403. Path traversal attempts are logged. Unlisted C2 domains that bypass DNS filtering are caught at the HTTP layer — demonstrating defense-in-depth between the two Layer 7 techniques.

---

## Notes
- The blocklist is shared between DNS and HTTP layers — loaded once at startup, read-only, no locking required
- Both implementations use the same `is_blocked()` function from `dns/dns.c`
- HTTPS traffic is **not** inspected at this layer — that is handled by Layer 6 (TLS Inspection, D3-TLSIC)