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
// these come directly from the RFCs you just read
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

// reuse hostname max length from RFC 1035
#define TLS_MAX_HOSTNAME_LEN            253


// --- task struct ---
// same pattern as dns_task_t and http_task_t
// think about: what does each thread need?
//   - the raw packet bytes (to parse)
//   - how many bytes were captured
//   - the source IP address (for logging)
//   - the extracted hostname (filled in by extract_sni())
typedef struct {
    unsigned char buffer[TLS_BUFFER_SIZE];   // raw captured packet
    int packet_len;                          // how many bytes captured
    struct sockaddr_in src_addr;             // who sent this packet
    char hostname[TLS_MAX_HOSTNAME_LEN];     // filled in by extract_sni()
} tls_task_t;


// --- function signatures ---
// implement these in tls_inspector.c


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

#endif
