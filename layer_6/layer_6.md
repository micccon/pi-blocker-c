# Layer 6 — Presentation Layer

## OSI Context
The Presentation Layer is responsible for data translation, encryption, and formatting. It ensures that data sent by one system can be read by another — handling encoding, compression, and cryptography. In modern networking, this layer is where TLS (Transport Layer Security) lives, providing encryption for application data before it travels over the network.

---

## D3FEND Technique

- **ID**: D3-TLSIC
- **Name**: TLS Inspection
- **Tactic**: Detect
- **Definition**: Intercepting and analyzing TLS handshake traffic to identify the intended destination hostname via the Server Name Indication (SNI) extension, enabling detection and filtering of encrypted connections to malicious domains before the encrypted tunnel is established.

---

## Digital Artifact
TLS ClientHello Record — specifically the SNI (Server Name Indication) extension extracted from the plaintext TLS handshake before encryption is established. Defined in RFC 8446 section 4.1.2 and RFC 6066 section 3.

---

## ATT&CK Mapping
- **Technique ID**: T1573
- **Technique Name**: Encrypted Channel
- **Why**: Adversaries use TLS-encrypted channels to blend command and control traffic with legitimate HTTPS traffic, making it invisible to application-layer inspection. SNI inspection catches the destination hostname before encryption begins, exposing C2 domains even over HTTPS.

---

## What This Implementation Does
The TLS inspector opens a raw TCP socket and passively captures all TCP packets arriving on the network interface. For each packet it skips past the IP and TCP headers to reach the TLS payload, checks whether the packet is a TLS ClientHello, and if so parses the byte structure of the ClientHello to locate and extract the SNI hostname extension. The hostname is then checked against the same blocklist used by Layer 7. Blocked hostnames are logged as alerts. This is passive detection — traffic is observed but not modified at this layer.

---

## Architecture
```
Raw TCP packet arrives on interface
         ↓
  Raw socket captures packet (SOCK_RAW, IPPROTO_TCP)
         ↓
  Filter: destination port == 443?
    NO  → discard
    YES → continue
         ↓
  Skip IP header (length from IHL field)
  Skip TCP header (length from data offset field)
         ↓
  is_tls_client_hello()
    Check byte 0 == 0x16 (handshake content type)
    Check byte 5 == 0x01 (ClientHello handshake type)
    NO  → discard
    YES → continue
         ↓
  extract_sni()
    Skip: legacy_version (2), random (32)
    Skip: session_id (variable), cipher_suites (variable)
    Skip: compression_methods (variable)
    Walk extensions until SNI type (0x0000) found
    Extract hostname bytes → lowercase
         ↓
  is_blocked(hostname)
    YES → log [BLOCKED] d3fend=D3-TLSIC attck=T1573
    NO  → log [ALLOWED] d3fend=D3-TLSIC
```

---

## Passive vs Active Detection

This layer is **passive** (IDS-style) unlike Layer 7 which is **active** (IPS-style):

| | Layer 7 HTTP Proxy | Layer 6 TLS Inspector |
|---|---|---|
| Traffic flows through it | ✅ Yes | ❌ No |
| Can block traffic directly | ✅ Yes | ❌ No |
| Modifies packets | ✅ Yes | ❌ No |
| Requires proxy configuration | ✅ Yes | ❌ No |
| Works on encrypted traffic | ❌ No | ✅ Yes (hostname only) |

Blocking based on Layer 6 detections is handed off to Layer 4 (port filter / firewall rules).

---

## Defense in Depth With Layer 7

| Scenario | Layer 7 Catches It | Layer 6 Catches It |
|---|---|---|
| HTTP request to blocked domain | ✅ | ❌ |
| HTTPS request to blocked domain | ❌ | ✅ |
| HTTPS request, SNI absent | ❌ | ❌ |
| New domain not on blocklist | ❌ | ❌ |

Layers 6 and 7 together cover both HTTP and HTTPS traffic by hostname.

---

## Files
- `tls_inspector/main.c` — loads blocklist, calls start_tls_inspector()
- `tls_inspector/tls_inspector.c` — raw socket setup, packet capture, SNI parsing, blocklist check
- `tls_inspector/tls_inspector.h` — structs, constants, function signatures

---

## Key Structs

### `struct tls_record_hdr` — RFC 8446 section 5.1
```
content_type  (1 byte)  — 0x16 = handshake
version       (2 bytes) — legacy, usually 0x0301
length        (2 bytes) — length of payload after header
```

### `struct tls_handshake_hdr` — RFC 8446 section 4
```
handshake_type  (1 byte)  — 0x01 = ClientHello
length          (3 bytes) — length of handshake body
```

### `tls_task_t`
```
buffer      — raw captured packet bytes
packet_len  — bytes captured
src_addr    — source IP address
hostname    — extracted SNI hostname
```

---

## Constants
| Constant | Value | Source |
|---|---|---|
| TLS_CONTENT_TYPE_HANDSHAKE | 0x16 | RFC 8446 Appendix B.1 |
| TLS_HANDSHAKE_CLIENT_HELLO | 0x01 | RFC 8446 Appendix B.3 |
| TLS_EXT_SNI | 0x0000 | RFC 6066 Section 3 |
| TLS_SNI_HOST_NAME | 0x00 | RFC 6066 Section 3 |
| TLS_RECORD_HEADER_SIZE | 5 | RFC 8446 Section 5.1 |
| TLS_HANDSHAKE_HEADER_SIZE | 4 | RFC 8446 Section 4 |

---

## How to Run
```bash
cd layer_6/tls_inspector
make
sudo ./tls-inspector   # raw sockets require root

# Test from another machine or browser:
# Visit any https:// site — inspector will log the SNI hostname
# Visit a blocked https:// domain — inspector will log BLOCKED
```

---

## Example Log Output
```
[2025-01-07 23:45:12] [LAYER_6] [TLS] [BLOCKED] host=ads.doubleclick.net src=192.168.1.5 d3fend=D3-TLSIC attck=T1573
[2025-01-07 23:45:13] [LAYER_6] [TLS] [ALLOWED] host=google.com          src=192.168.1.5 d3fend=D3-TLSIC
```

---

## Limitations
- Cannot decrypt or inspect HTTPS request contents — only the SNI hostname
- Some clients omit SNI (rare but possible) — these connections pass through undetected
- TLS 1.3 encrypts the certificate but SNI remains plaintext in ClientHello
- ESNI/ECH (Encrypted Client Hello, RFC 9258) would defeat this technique entirely — a known gap
- Blocking requires coordination with Layer 4 firewall — this layer detects only

---

## Phase 2 — Planned Attack
- **Tool**: `openssl s_client`, custom Python TLS client
- **Method**: Connect to known blocked domains over HTTPS, observe whether SNI is detected. Then attempt to connect without SNI to test the gap.
- **Expected Result**: Standard HTTPS connections to blocked domains are detected and logged. Connections without SNI bypass Layer 6 — demonstrating why multiple layers are necessary.