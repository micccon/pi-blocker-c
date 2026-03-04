#ifndef SESSION_TRACKER_H
#define SESSION_TRACKER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include "../common/net_hdrs.h"

// --- constants ---
// number of hash buckets — use a prime to reduce collisions
#define SESSION_TABLE_SIZE      1021

// time window in seconds — how long before SYN counter resets
#define SESSION_WINDOW_SECONDS  60

// max SYNs from one IP within the window before flagging as flood
#define SESSION_SYN_THRESHOLD   80

// max total entries across all buckets
#define SESSION_MAX_ENTRIES     4096

// max size for buffer
#define SESSION_BUFFER_SIZE     4096

// hash multipliers for tuple mixing (Knuth golden ratio)
#define SESSION_HASH_DST_MULTIPLIER   2654435761u
#define SESSION_HASH_PORT_MULTIPLIER  2246822519u

// --- session entry ---
// one tracked IP in the hash table
// uses chaining for collision resolution
typedef struct session_entry {
    uint32_t src_ip;              // source IP address (network byte order)
    uint32_t dst_ip;              // destination IP address (network byte order)
    uint16_t dst_port;            // destination TCP port (network byte order)
    int syn_count;               // how many SYNs seen in current window
    time_t window_start;         // when the current window started
    bool blocked;                // whether this IP is currently blocked
    struct session_entry *next;  // pointer to next entry in the bucket chain
} session_entry_t;


// --- session table ---
// hint: array of bucket heads, total entry count, mutex for thread safety
typedef struct {
    session_entry_t *buckets[SESSION_TABLE_SIZE];
    int total_entries;
    pthread_mutex_t lock;
} session_table_t;


// --- task struct ---
// same pattern as tls_task_t and http_task_t
typedef struct {
    unsigned char buffer[SESSION_BUFFER_SIZE];   // raw captured packet
    int packet_len;                          // how many bytes captured
    struct sockaddr_in src_addr;             // who sent this packet
} session_task_t;


// --- function signatures ---

// opens raw socket, captures TCP SYN packets, spawns threads
void start_session_tracker();

// initializes hash table — zeros buckets, inits mutex
// call once at startup before any lookups or inserts
void session_table_init(session_table_t *table);

// looks up an entry by source/destination tuple
// returns pointer to entry if found, NULL if not present
// caller must hold table->lock
session_entry_t* session_lookup(session_table_t *table, uint32_t src_ip,
                                uint32_t dst_ip, uint16_t dst_port);

// inserts a new entry for src/dst/port tuple
// returns pointer to new entry, NULL if table is full or alloc fails
// caller must hold table->lock
session_entry_t* session_insert(session_table_t *table, uint32_t src_ip,
                                uint32_t dst_ip, uint16_t dst_port);

// main rate limit check — call this on every SYN packet
// looks up or inserts src/dst/port tuple, increments syn_count
// resets counter if window has expired
// returns negative syn_count on first block transition
// returns positive syn_count when allowed or already blocked
// returns 0 if insert failed (table full / alloc failure)
// handles its own locking internally
int check_syn_flood(session_table_t *table, uint32_t src_ip,
                    uint32_t dst_ip, uint16_t dst_port);

// frees all entries and destroys mutex
// call on shutdown
void session_table_cleanup(session_table_t *table);

// thread entry point
// extracts src_ip from packet, calls check_syn_flood, logs result
void* handle_session_packet(void *arg);

// structured log line
// [TIMESTAMP] [LAYER_5] [SESSION] [ACTION] src=X syn_count=N d3fend=D3-CSLL attck=T1499
void log_session_decision(const char *action, session_task_t *task,
                          uint32_t src_ip, int syn_count);

// Layer 4 enforcement hook — same pattern as Layer 6
// TODO: implement after Layer 4
void session_enforce_block(uint32_t src_ip);

#endif
