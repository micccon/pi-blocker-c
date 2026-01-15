#ifndef DNS_H
#define DNS_H

#include <stdint.h> // Required for uint16_t
#include <stdbool.h>
#include <stddef.h>

// Masks for the Flags field
#define DNS_FLAG_QR     0x8000  // 1000 0000 0000 0000 (The very first bit)
#define DNS_FLAG_OPCODE 0x7800  // 0111 1000 0000 0000
#define DNS_FLAG_AA     0x0400  // 0000 0100 0000 0000
#define DNS_FLAG_RD     0x0100  // 0000 0001 0000 0000
#define DNS_FLAG_RCODE  0x000F  // 0000 0000 0000 1111 (The last 4 bits)

// Constants used in main.c and dns.c
#define DNS_PORT 53
#define DNS_BUFFER_SIZE 512
#define DNS_NAME_SIZE 256
#define UPSTREAM_BUFFER_SIZE 65536
#define BLOCKLIST_LINE_BUFFER 256
#define MAX_LOOP_COUNT 100
#define JUMP_HEX_VALUE 0xC0
#define FIRST_OFFSET_HEX_VALUE 0x3F

// Global blocklist variables
extern char **g_blocklist;
extern size_t g_blocklist_size;

/* * DNS Header Structure (RFC 1035)
 * Total Size: 12 Bytes
 * All fields are 16-bit integers (uint16_t)
 * WARNING: Data comes in Big-Endian (Network Byte Order).
 * You must use ntohs() to read the numbers correctly.
 */
struct dns_hdr {
    uint16_t id;          // Transaction ID: Matches the query to the response.
    uint16_t flags;       // Flags & Codes: Contains QR, Opcode, AA, TC, RD, RA, Z, RCODE.
                          // (We will use bitwise math to read the specific bits later)
    uint16_t qdcount;     // Question Count: How many questions are we asking? (Usually 1)
    uint16_t ancount;     // Answer Count: How many answers is the server sending back?
    uint16_t nscount;     // Authority Count: How many "Authority" servers (NS records) are listed?
    uint16_t arcount;     // Additional Count: How many "Extra" records (like glue records) are included?
};

// -------------------------- DNS PARSER -----------------------------

/**
 * Reads a DNS Domain Name from the packet, handling both standard labels
 * (e.g., 3www6google3com0).
 *
 * @param reader  Pointer to the current location in the packet where the name starts.
 * @param buffer  Pointer to the start of the full packet (needed for jumping to compressed offsets).
 * @param count   [Output] Stores the number of bytes read/advanced. The caller should use this
 * to move their pointer past the name after reading.
 *
 * @return A dynamically allocated string (e.g., "www.google.com").
 * WARNING: The caller is responsible for freeing this memory!
 */
unsigned char* read_name(unsigned char* reader, unsigned char* buffer, int* count);

// -------------------------- BLOCKLIST ENGINE -----------------------------

/**
 * Loads a text file of domains into memory and prepares them for searching.
 * Expects a file with one domain per line.
 * * @param filename The path to the blocklist file (e.g., "blocklist.txt").
 */
void load_blocklist(const char *filename);

/**
 * Checks if a hostname exists in the loaded blocklist.
 * Uses Binary Search for high performance.
 * @param host The hostname to check (e.g., "ads.google.com").
 * @return TRUE if the host is BLOCKED, FALSE if ALLOWED.
 */
bool is_blocked(char *host);

/**
 * Frees all memory associated with the blocklist.
 * Call this before the program exits to be clean.
 */
void free_blocklist();

#endif
