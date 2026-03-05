#ifndef ARP_H
#define ARP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include "../common/net_hdrs.h"
#include "../common/enforce.h"

// --- constants ---

// number of hash buckets — doesn't need to be prime since MAC/IP
// distribution is already fairly random
#define ARP_TABLE_SIZE        256

// max total entries across all buckets before we stop inserting
#define ARP_ENTRY_MAX         1024

// max Ethernet frame size — standard MTU 1500 + 14 byte header + 4 byte FCS
#define ARP_BUFFER_SIZE       1518

// how long before an IP→MAC mapping is considered stale
// stale entries are candidates for eviction on next insert
#define ARP_STALE_SECONDS     300


// --- arp entry ---
// one IP→MAC mapping in the ARP table
// last_seen updated every time we see a consistent mapping
// inconsistent mapping (same IP, different MAC) triggers spoof alert
typedef struct arp_entry {
    uint32_t          ip;        // IP address in network byte order
    uint8_t           mac[6];    // known MAC address for this IP
    time_t            last_seen; // timestamp of last confirmed sighting
    struct arp_entry *next;      // next entry in bucket chain
} arp_entry_t;


// --- arp table ---
// hash table mapping IP addresses to known MAC addresses
// all access protected by mutex — multiple threads process packets concurrently
typedef struct arp_table {
    arp_entry_t    *buckets[ARP_TABLE_SIZE];
    int             total_entries;
    pthread_mutex_t lock;
} arp_table_t;


// --- arp task ---
// raw Ethernet frame passed to each handler thread
// buffer holds full frame including Ethernet header + ARP payload
typedef struct arp_task {
    unsigned char      buffer[ARP_BUFFER_SIZE];
    int                packet_len;
    struct sockaddr_ll src_addr;  // AF_PACKET uses sockaddr_ll not sockaddr_in
} arp_task_t;


// --- function signatures ---

// opens AF_PACKET raw socket, captures all Ethernet frames
// filters for ARP replies (ethertype 0x0806, oper == 2)
// spawns one thread per ARP reply
void start_arp_monitor();

// initializes hash table — zeros buckets, sets total_entries, inits mutex
// call once at startup
void arp_table_init(arp_table_t *table);

// looks up an entry by IP address
// returns pointer to entry if found, NULL if not present
// caller must hold table->lock
arp_entry_t* arp_lookup(arp_table_t *table, uint32_t ip);

// inserts a new IP→MAC mapping at head of bucket chain
// returns pointer to new entry, NULL if table full or alloc fails
// caller must hold table->lock
arp_entry_t* arp_insert(arp_table_t *table, uint32_t ip, uint8_t mac[6]);

// updates last_seen and MAC of an existing entry
// caller must hold table->lock
void arp_update(arp_entry_t *entry, uint8_t mac[6]);

// main spoof detection logic — call on every ARP reply
// looks up sender IP in table
// if known IP has different MAC → spoof detected → returns 1
// if new IP → inserts mapping → returns 0
// if same MAC → updates last_seen → returns 0
// if insert fails (table full or alloc failure) → returns -1
// handles its own locking internally
int check_arp_spoof(arp_table_t *table, uint32_t sender_ip,
    uint8_t sender_mac[6], uint8_t old_mac_out[6]);

// frees all entries in all buckets and destroys mutex
// call on shutdown
void arp_table_cleanup();

// thread entry point
// extracts sender IP and MAC from ARP reply
// calls check_arp_spoof()
// logs result — ALERT if spoof detected, LEARNED if new mapping, OK if consistent
void* handle_arp_packet(void *arg);

// structured log line
// [TIMESTAMP] [LAYER_2] [ARP] [ACTION] ip=X mac=X d3fend=D3-AAF attck=T1557.002
void log_arp_decision(const char *action, uint32_t ip,
                      uint8_t mac[6], uint8_t old_mac[6]);

#endif
