#ifndef ENFORCE_H
#define ENFORCE_H

// --- includes ---
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// --- constants ---
// dedicated chain for all project-enforced rules
#define ENFORCE_CHAIN_NAME "PI_BLOCKER"
// max shell command length for iptables commands
#define ENFORCE_CMD_LEN 320
// hash bucket counts for each tracked key type
#define ENFORCE_IP_BUCKETS 1021
#define ENFORCE_PORT_BUCKETS 1021
#define ENFORCE_PROTO_BUCKETS 127

// --- hash entry structs ---
// linked-list entry for blocked source IPs
typedef struct ip_entry {
    uint32_t ip_nbo;
    struct ip_entry *next;
} ip_entry_t;

// linked-list entry for blocked destination port + protocol pairs
typedef struct port_entry {
    uint16_t port_hbo;
    uint8_t proto_num;
    struct port_entry *next;
} port_entry_t;

// linked-list entry for blocked protocols
typedef struct proto_entry {
    uint8_t proto_num;
    struct proto_entry *next;
} proto_entry_t;

// --- public API ---
// src_ip_nbo uses network byte order (from packet headers).
// port_hbo uses host byte order (normal C integer port values).
// proto_num uses IP protocol numbers (e.g., IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP).
int block_ip(uint32_t src_ip_nbo);
int block_port(uint16_t port_hbo, uint8_t proto_num);
int block_proto(uint8_t proto_num);

bool is_ip_blocked(uint32_t src_ip_nbo);
bool is_port_blocked(uint16_t port_hbo, uint8_t proto_num);
bool is_proto_blocked(uint8_t proto_num);

// sends TCP RST to terminate a connection
// src_ip/dst_ip are expected in network byte order
// src_port/dst_port are expected in host byte order
// ack_num is expected in network byte order (from captured TCP ACK field)
void rst_inject(int raw_fd, uint32_t src_ip, uint16_t src_port,
                uint32_t dst_ip, uint16_t dst_port, uint32_t ack_num);

void enforce_cleanup(void);

#endif
