// link_monitor.h

#ifndef LINK_MONITOR_H
#define LINK_MONITOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "../common/enforce.h"

// --- constants ---

// netlink receive buffer size
#define LINK_BUFFER_SIZE      4096

// how many link events to track per interface before rotating
#define LINK_EVENT_MAX        64

// seconds between repeated alerts for the same interface
// prevents log spam on flapping links
#define LINK_ALERT_COOLDOWN   10


// --- link state ---
typedef enum {
    LINK_STATE_UNKNOWN = 0,
    LINK_STATE_UP,        // IFF_UP + IFF_RUNNING — normal
    LINK_STATE_DOWN,      // IFF_UP set, IFF_RUNNING clear — carrier lost
    LINK_STATE_DISABLED,  // IFF_UP clear — interface disabled
} link_state_t;


// --- link entry ---
// tracks state history for one network interface
typedef struct link_entry {
    char           ifname[IFNAMSIZ];  // interface name e.g. "eth0"
    int            ifindex;           // kernel interface index
    link_state_t   last_state;        // last known state
    time_t         last_event;        // timestamp of last state change
    time_t         last_alert;        // timestamp of last alert — for cooldown
    int            flap_count;        // how many times link has gone down
    struct link_entry *next;          // chain for hash collisions
} link_entry_t;


// --- link table ---
// small hash table of tracked interfaces
// keyed by interface index
#define LINK_TABLE_SIZE  16

typedef struct {
    link_entry_t   *buckets[LINK_TABLE_SIZE];
    int             total_entries;
    pthread_mutex_t lock;
} link_table_t;


// --- function signatures ---

// opens netlink socket, binds to RTMGRP_LINK multicast group
// blocks on recvmsg() waiting for RTM_NEWLINK events
// same event-driven pattern as every other layer
void start_link_monitor();

// initializes link table — zeros buckets, inits mutex
void link_table_init(link_table_t *table);

// looks up entry by interface index
// returns pointer to entry if found, NULL if not present
// caller must hold table->lock
link_entry_t* link_lookup(link_table_t *table, int ifindex);

// inserts new entry for interface
// returns pointer to new entry, NULL on alloc failure
// caller must hold table->lock
link_entry_t* link_insert(link_table_t *table, int ifindex, const char *ifname);

// main detection logic
// called on every RTM_NEWLINK event
// computes new link_state_t from ifi_flags
// compares to last known state
// returns 1 if state changed, 0 if same
int check_link_state(link_table_t *table, int ifindex,
                     const char *ifname, unsigned int ifi_flags);

// frees all entries, destroys mutex
void link_table_cleanup();

// structured log line
// [TIMESTAMP] [LAYER_1] [LINK] [ACTION] iface=X state=X flaps=N d3fend=D3-NTA attck=T1200
void log_link_event(const char *action, link_entry_t *entry,
                    link_state_t old_state, link_state_t new_state);

#endif
