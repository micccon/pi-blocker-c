#ifndef IP_FILTER_H
#define IP_FILTER_H

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
#include "../common/net_hdrs.h"
#include "../common/enforce.h"
#include "../common/reputation.h"

// --- constants ---
// raw packet capture buffer size
#define IP_REP_BUFFER_SIZE    4096

// default path to reputation feed file
// one IP or CIDR per line — e.g. "1.2.3.4" or "1.2.3.0/24"
#define IP_REP_FILE           "../reputation/reputation.txt"


// --- task struct ---
// passed to each packet handler thread
// same pattern as every other layer
typedef struct {
    unsigned char      buffer[IP_REP_BUFFER_SIZE];
    int                packet_len;
    struct sockaddr_in src_addr;
} ip_task_t;


// --- function signatures ---

// opens raw socket, captures all IP packets, spawns threads
// same role as start_session_tracker() and start_port_filter()
void start_ip_filter();

// enable or disable verbose per-packet allowed logging
void ip_filter_set_verbose(bool verbose);

// signal-safe stop request
// asks start_ip_filter() loop to exit cleanly
void request_ip_filter_stop(void);

// wrapper for common/reputation load path
// returns number of entries loaded, -1 on failure
int load_reputation(const char *path);

// wrapper for common/reputation matcher
// returns 1 if src_ip matches a reputation entry, 0 if clean
int check_ip_reputation(uint32_t src_ip);

// frees reputation list and calls enforce_cleanup()
// register with SIGINT/SIGTERM signal handler in main.c
void ip_filter_cleanup();

// thread entry point
// extracts src_ip from IP header
// calls check_ip_reputation()
// calls block_ip() and logs if match found
void* handle_ip_packet(void *arg);

// structured log line
// [TIMESTAMP] [LAYER_3] [IP_REP] [ACTION] src=X d3fend=D3-ITF attck=T1590
void log_ip_decision(const char *action, ip_task_t *task, uint32_t src_ip);

#endif
