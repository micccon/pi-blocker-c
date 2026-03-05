#ifndef REPUTATION_H
#define REPUTATION_H

// --- includes ---
#include <stdint.h>

// --- reputation entry ---
// network stored in host byte order for arithmetic matching
typedef struct {
    uint32_t network;
    uint8_t  prefix;
} reputation_entry_t;

// --- public API ---
// load IP/CIDR entries from file path
// returns number of entries loaded, -1 on fatal error
int reputation_load(const char *path);

// check src_ip (network byte order) against loaded entries
// returns 1 on match, 0 on no match
int reputation_match_ip(uint32_t src_ip_nbo);

// current loaded entry count
int reputation_entry_count(void);

// clear in-memory reputation entries
void reputation_cleanup(void);

#endif
