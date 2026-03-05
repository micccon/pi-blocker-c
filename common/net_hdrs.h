#ifndef NET_HEADERS_H
#define NET_HEADERS_H

#include <stdint.h>
#include <linux/if_ether.h>

// ethertype constants
#define ETHERTYPE_ARP   0x0806
#define ETHERTYPE_IPV4  0x0800

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

// Ethernet header — IEEE 802.3
struct eth_hdr {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype; // e.g., 0x0800 for IPv4
} __attribute__((packed));

// ARP packet — RFC 826
struct arp_pkt {
    uint16_t htype;       // hardware type (1 for Ethernet)
    uint16_t ptype;       // protocol type (0x0800 for IPv4)
    uint8_t hlen;         // hardware address length (6 for Ethernet)
    uint8_t plen;         // protocol address length (4 for IPv4)   
    uint16_t oper;        // operation (1 for request, 2 for reply)
    uint8_t sha[6];       // sender hardware address (MAC)
    uint32_t spa;         // sender protocol address (IP)
    uint8_t tha[6];       // target hardware address (MAC)
    uint32_t tpa;         // target protocol address (IP)
} __attribute__((packed));    

#endif
