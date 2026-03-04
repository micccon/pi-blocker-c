#ifndef TLS_INSPECTOR_H
#define TLS_INSPECTOR_H

// --- includes ---
// same as proxy.h — you need threading, sockets, string ops, time
// one new one you'll need: look up what header provides uint8_t, uint16_t
// hint: you already included it in dns.h
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#include <netdb.h>
#include "../common/net_hdrs.h"

// --- constants ---
// --- TLS version constants ---
// RFC 8446 Appendix B — legacy_version values
#define TLS_VERSION_1_0     0x0301
#define TLS_VERSION_1_1     0x0302
#define TLS_VERSION_1_2     0x0303
#define TLS_VERSION_1_3     0x0304
#define TLS_MIN_VERSION     TLS_VERSION_1_2   // block anything older than this

// --- extension type constants ---
// RFC 7301 — Application Layer Protocol Negotiation
#define TLS_EXT_ALPN        0x0010
// RFC 8446 section 4.2.1 — supported versions extension
#define TLS_EXT_SUPPORTED_VERSIONS 0x002B

// --- policy thresholds ---
#define TLS_MAX_EXTENSION_COUNT     30    // alert if more than this
#define TLS_MAX_CLIENTHELLO_SIZE    2048  // alert if larger than this

// RFC 8446 Appendix B.1 — content type for handshake records
#define TLS_CONTENT_TYPE_HANDSHAKE      0x16

// RFC 8446 Appendix B.3 — handshake type for ClientHello
#define TLS_HANDSHAKE_CLIENT_HELLO      0x01

// RFC 6066 Section 3 — extension type number for SNI
#define TLS_EXT_SNI                     0x0000

// RFC 6066 Section 3 — name type for hostname
#define TLS_SNI_HOST_NAME               0x00

// TLS record header is always 5 bytes
// RFC 8446 section 5.1 — content_type(1) + version(2) + length(2)
#define TLS_RECORD_HEADER_SIZE          5

// TLS handshake header is 4 bytes
// RFC 8446 section 4 — type(1) + length(3)
#define TLS_HANDSHAKE_HEADER_SIZE       4

// max buffer for capturing raw packets
// TLS ClientHello fits comfortably in 4096 bytes
#define TLS_BUFFER_SIZE                 4096

// what port does HTTPS run on?
#define HTTPS_PORT                      443
// HTTPS over explicit proxy (CONNECT tunnel payload on proxy listener)
#define HTTP_PROXY_PORT                 8080

// reuse hostname max length from RFC 1035
#define TLS_MAX_HOSTNAME_LEN            253

// --- bounds check macro ---
#define CHECK_BOUNDS(pos, needed, length) \
    do { if ((pos) + (needed) > (length)) return -1; } while (0)

#define CHECK_BOUNDS_ZERO(pos, needed, length) \
    do { if ((pos) + (needed) > (length)) return 0; } while (0)

// --- policy verdicts ---
typedef enum {
    POLICY_PASS              = 0,
    POLICY_ALERT_NO_SNI      = 1,   // missing SNI — alert-only until reassembly
    POLICY_BLOCK_OLD_TLS     = 2,   // TLS version < 1.2 — T1573
    POLICY_ALERT_ALPN        = 3,   // suspicious ALPN — T1071
    POLICY_ALERT_EXT_COUNT   = 4,   // anomalous extension count
    POLICY_ALERT_LARGE_HELLO = 5,   // oversized ClientHello
    POLICY_BLOCK_BLOCKLIST   = 6,   // hostname matched local deny list
} tls_policy_verdict_t;

// --- task struct ---
typedef struct {
    unsigned char buffer[TLS_BUFFER_SIZE];   // raw captured packet
    int packet_len;                          // how many bytes captured
    struct sockaddr_in src_addr;             // who sent this packet
    char hostname[TLS_MAX_HOSTNAME_LEN];     // filled in by extract_sni()

    // --- policy fields filled by parse_client_hello() ---
    uint16_t      tls_version;          // legacy_version from ClientHello
    int           raw_fd;               // raw socket fd for potential RST injection
    int           sni_present;          // 1 if SNI found, 0 if missing
    char          alpn[64];             // ALPN value if present
    int           extension_count;      // total number of extensions
    int           client_hello_size;    // total ClientHello size in bytes
    int           parse_complete;       // 1 only when full TLS record is present
    tls_policy_verdict_t verdict;       // result of policy check
} tls_task_t;

// opens raw socket, captures packets in a loop, spawns threads
// same role as start_proxy_server() in Layer 7
// but uses recvfrom() not accept() — why? think about the socket type
void start_tls_inspector();

// checks if a raw packet contains a TLS ClientHello
// looks at content type byte and handshake type byte
// returns 1 if yes, 0 if no
//
// @param buffer    raw packet bytes
// @param len       number of bytes in buffer
int is_tls_client_hello(unsigned char *buffer, int len);

// walks through TLS record bytes and extracts the SNI hostname
// this is the core parsing function — similar to read_name() in dns.c
// returns 0 on success, -1 if SNI extension not found
//
// @param buffer        raw packet bytes starting at TLS record
// @param len           total bytes available
// @param hostname      output buffer to write hostname into
// @param hostname_len  size of hostname buffer
//
// WARNING: caller is responsible for hostname buffer size
int extract_sni(unsigned char *buffer, int len,
                char *hostname, int hostname_len);

// thread entry point — same pattern as handle_dns_request()
// calls is_tls_client_hello() → extract_sni() → is_blocked() → log
void* handle_tls_packet(void *arg);

// structured log line — same format as Layer 7
// [TIMESTAMP] [LAYER_6] [TLS] [BLOCKED/ALLOWED] host=X src=X d3fend=D3-TLSIC attck=T1573
void log_decision(const char *action, tls_task_t *task);

// sends a TCP RST to terminate a connection
// call this after detecting a blocked SNI
// raw_fd   — your existing raw socket from start_tls_inspector()
// task     — the captured packet task
void send_tcp_rst(int raw_fd, tls_task_t *task);

// replaces is_tls_client_hello() — parses ClientHello and fills task metadata
// returns 1 if ClientHello, 0 if not
int parse_client_hello(unsigned char *buffer, int len, tls_task_t *task);

// runs all policy checks against parsed ClientHello metadata
// returns POLICY_PASS or a violation code
tls_policy_verdict_t check_tls_policy(tls_task_t *task);

// extracts ALPN extension value into task->alpn
// RFC 7301 — Application Layer Protocol Negotiation
// returns 0 on success, -1 if not found
int extract_alpn(unsigned char *buffer, int len, tls_task_t *task);

// Layer 4 enforcement hook — logs intent, implement RST after Layer 4
// called when policy check returns a block verdict
void enforce_block(tls_task_t *task);

// updated log — now includes verdict reason
void log_policy_decision(tls_policy_verdict_t verdict, tls_task_t *task);

#endif
