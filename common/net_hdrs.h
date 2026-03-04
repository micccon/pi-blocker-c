#ifndef NET_HEADERS_H
#define NET_HEADERS_H

#include <stdint.h>

// RFC 791 — IP header
struct ip_hdr {
    uint8_t  version_ihl;      // upper 4 bits = version, lower 4 bits = IHL
    uint8_t  tos;              // type of service
    uint16_t total_length;     // total length of packet
    uint16_t id;               // identification
    uint16_t flags_fragment;   // upper 3 bits = flags, lower 13 = fragment offset
    uint8_t  ttl;              // time to live
    uint8_t  protocol;         // TCP=6, UDP=17, ICMP=1
    uint16_t checksum;         // header checksum
    uint32_t src_addr;         // source IP address
    uint32_t dst_addr;         // destination IP address
} __attribute__((packed));

// RFC 793 — TCP header
struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset;  // upper 4 bits = header length in 32-bit words
    uint8_t  flags;        // SYN, ACK, FIN, RST, PSH, URG
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} __attribute__((packed));

// RFC 768 — UDP header
struct udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed));

// RFC 1035 — DNS header (12 bytes)
struct dns_hdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));

// RFC 8446 — TLS record header (5 bytes)
struct tls_record_hdr {
    uint8_t content_type;
    uint16_t version;
    uint16_t length;
} __attribute__((packed));

// RFC 8446 — TLS handshake header (4 bytes)
struct tls_handshake_hdr {
    uint8_t handshake_type;
    uint8_t length[3];
} __attribute__((packed));

// Layer 2 structs — fill in when you get there
// struct eth_hdr
// struct arp_pkt

#endif
