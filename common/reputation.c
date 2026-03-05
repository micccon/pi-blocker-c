#include "reputation.h"

// --- includes ---
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// --- constants ---
#define REPUTATION_MAX_ENTRIES 4096

// --- global reputation list ---
// loaded once at startup; read-only during packet processing
static reputation_entry_t g_rep_list[REPUTATION_MAX_ENTRIES];
static int g_rep_count = 0;

// --- helper: CIDR match ---
static int cidr_match(uint32_t src_hbo, uint32_t network_hbo, uint8_t prefix)
{
    // --- compute subnet mask from prefix length ---
    uint32_t mask = (prefix == 0) ? 0 : (~0u << (32 - prefix));

    // --- mask both addresses and compare ---
    return (src_hbo & mask) == (network_hbo & mask);
}

// --- helper: sort by network address ---
static int compare_entries(const void *a, const void *b)
{
    const reputation_entry_t *entry_a = (const reputation_entry_t *)a;
    const reputation_entry_t *entry_b = (const reputation_entry_t *)b;

    return (entry_a->network > entry_b->network) - (entry_a->network < entry_b->network);
}

int reputation_load(const char *path)
{
    // --- open file ---
    FILE *file = fopen(path, "r");
    if (!file)
    {
        perror("Could not open reputation file");
        return -1;
    }

    // --- reset previous state ---
    memset(g_rep_list, 0, sizeof(g_rep_list));
    g_rep_count = 0;

    // --- read line by line ---
    while (g_rep_count < REPUTATION_MAX_ENTRIES && !feof(file))
    {
        char line[256];
        if (!fgets(line, sizeof(line), file))
            break;

        // --- strip inline comment suffix ---
        char *comment = strchr(line, '#');
        if (comment) *comment = '\0';

        // --- skip blank lines and comments ---
        if (strspn(line, " \t\n\r") == strlen(line) || line[0] == '#')
            continue;

        // --- strip trailing newline (handles LF and CRLF) ---
        line[strcspn(line, "\r\n")] = '\0';

        if (strchr(line, '/'))  // CIDR range
        {
            // --- split on slash ---
            char *slash = strchr(line, '/');
            *slash = '\0';
            char *network_str = line;
            char *prefix_str = slash + 1;

            // --- parse network address ---
            struct in_addr addr;
            if (inet_pton(AF_INET, network_str, &addr) != 1)
                continue;

            char *endptr = NULL;
            long prefix = strtol(prefix_str, &endptr, 10);
            if (endptr == prefix_str || *endptr != '\0' || prefix < 0 || prefix > 32)
                continue;

            // --- store in global list ---
            g_rep_list[g_rep_count].network = ntohl(addr.s_addr);
            g_rep_list[g_rep_count].prefix = (uint8_t)prefix;
        }
        else  // single IP
        {
            // --- trim trailing whitespace for single IP line ---
            char *ip_end = line + strlen(line);
            while (ip_end > line && (ip_end[-1] == ' ' || ip_end[-1] == '\t'))
                *--ip_end = '\0';

            // --- parse IP address ---
            struct in_addr addr;
            if (inet_pton(AF_INET, line, &addr) != 1)
                continue;

            // --- store as /32 in global list ---
            g_rep_list[g_rep_count].network = ntohl(addr.s_addr);
            g_rep_list[g_rep_count].prefix = 32;
        }

        g_rep_count++;
    }

    // --- sort list by network address for efficient searching ---
    qsort(g_rep_list, g_rep_count, sizeof(reputation_entry_t), compare_entries);

    fclose(file);
    return g_rep_count;
}

int reputation_match_ip(uint32_t src_ip_nbo)
{
    // --- convert to host byte order for comparison ---
    uint32_t src_hbo = ntohl(src_ip_nbo);

    // --- walk all entries checking CIDR match ---
    for (int i = 0; i < g_rep_count; i++)
    {
        if (cidr_match(src_hbo, g_rep_list[i].network, g_rep_list[i].prefix))
            return 1;  // match found
    }
    return 0;  // no match
}

int reputation_entry_count(void)
{
    return g_rep_count;
}

void reputation_cleanup(void)
{
    // --- zero the reputation list ---
    memset(g_rep_list, 0, sizeof(g_rep_list));
    g_rep_count = 0;
}
