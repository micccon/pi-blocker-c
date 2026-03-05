#ifndef FILTER_H
#define FILTER_H

#include "../common/net_hdrs.h"
#include "../common/enforce.h"

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

// --- constants ---
#define PORT_SCAN_TABLE_SIZE     1021
#define PORT_SCAN_WINDOW_SECONDS 10
#define PORT_SCAN_THRESHOLD      15
#define PORT_HISTORY_SIZE        32
#define PORT_BUFFER_SIZE         4096
#define PORT_SCAN_MAX_ENTRIES    4096

// --- TCP flag scan signatures ---
#define TCP_FLAG_SYN    0x02
#define TCP_FLAG_ACK    0x10
#define TCP_FLAG_FIN    0x01
#define TCP_FLAG_PSH    0x08
#define TCP_FLAG_URG    0x20
#define TCP_FLAG_RST    0x04

#define TCP_FLAGS_XMAS  (TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG)  // 0x29
#define TCP_FLAGS_NULL  0x00

// --- structs ---
// one tracked IP in the scan detection table
typedef struct port_scan_entry {
    uint32_t  src_ip;
    uint16_t  ports_seen[PORT_HISTORY_SIZE];  // circular buffer
    int       port_index;                      // next write position
    int       unique_ports;                    // distinct ports in window
    time_t    window_start;
    bool      flagged;
    struct port_scan_entry *next;
} port_scan_entry_t;

// the hash table
typedef struct {
    port_scan_entry_t *buckets[PORT_SCAN_TABLE_SIZE];
    int                total_entries;
    pthread_mutex_t    lock;
} port_scan_table_t;

// task struct
typedef struct {
    unsigned char      buffer[PORT_BUFFER_SIZE];
    int                packet_len;
    int                raw_fd;      // raw socket fd for optional RST injection
    struct sockaddr_in src_addr;
} port_task_t;

// --- function signatures ---

// opens raw socket, captures all TCP+UDP packets, spawns threads
// same role as start_session_tracker() in Layer 5
void start_port_filter();

// initializes hash table — zeros buckets, sets total_entries to 0, inits mutex
// call once at startup before any lookups or inserts
void port_scan_table_init(port_scan_table_t *table);

// looks up an existing entry by source IP
// returns pointer to entry if found, NULL if not present
// caller must hold table->lock
port_scan_entry_t* port_scan_lookup(port_scan_table_t *table, uint32_t src_ip);

// inserts a new entry for src_ip at head of hash bucket chain
// returns pointer to new entry, NULL if alloc fails
// caller must hold table->lock
port_scan_entry_t* port_scan_insert(port_scan_table_t *table, uint32_t src_ip);

// main scan detection logic — call on every packet
// looks up or inserts src_ip, adds dst_port to circular buffer
// counts unique ports in current window
// resets window if PORT_SCAN_WINDOW_SECONDS has elapsed
// returns negative unique_port count on first scan detection
// returns positive unique_port count for allowed or already-flagged traffic
// handles its own locking internally
int check_port_scan(port_scan_table_t *table, uint32_t src_ip, uint16_t dst_port);

// frees all entries in all buckets and destroys mutex
// call on shutdown
void port_scan_table_cleanup(port_scan_table_t *table);

// thread entry point — extracts src_ip and dst_port from raw packet
// detects scan type from TCP flags (SYN, NULL, XMAS, FIN)
// calls check_port_scan(), enforces block + RST on detection, logs result
void* handle_port_packet(void *arg);

// structured log line
// [TIMESTAMP] [LAYER_4] [PORT] [ACTION] src=X dst_port=N unique_ports=N d3fend=D3-NTCD attck=T1046
void log_port_decision(const char *action, port_task_t *task,
                       uint32_t src_ip, uint16_t dst_port, int unique_ports);

#endif
