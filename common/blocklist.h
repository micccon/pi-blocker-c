#ifndef BLOCKLIST_H
#define BLOCKLIST_H

#include <stdbool.h>

// Loads a text file of domains into memory.
// Returns 0 on success, -1 on failure.
int load_blocklist(const char *filename);

// Checks if host is in the blocklist.
// Matches exact host and parent domains.
bool is_blocked(const char *host);

// Frees all memory associated with the loaded blocklist.
void free_blocklist(void);

#endif
