#ifndef DNS_H
#define DNS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>

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

// -------------------------- DNS STRUCTS -----------------------------

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

/**
 * Data structure used to pass context to worker threads.
 * Since pthread_create only accepts a single pointer argument, this struct 
 * bundles everything a thread needs to process a DNS request independently.
 */
typedef struct {
    int client_socket;                      // The port we listen on
    struct sockaddr_in client_addr;         // Who sent the request
    unsigned char buffer[DNS_BUFFER_SIZE];  // Buffer for DNS queries
    ssize_t query_size;                     // Size of the DNS buffer
    struct sockaddr_in upstream_addr;       // Pre-configured Google/Cloudflare addr
} dns_task_t;

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

// -------------------------- DNS THREAD HANDLING -----------------------------

/**
 * The entry point for worker threads handling individual DNS queries.
 * * This function runs in its own thread to prevent "Head-of-Line Blocking."
 * It parses the domain, checks the blocklist, and either sends a REFUSED 
 * response or forwards the query to the upstream server via a thread-local socket.
 *
 * @param arg A pointer to a dns_task_t structure (must be cast to void*).
 * @return NULL upon completion. This function is responsible for freeing 'arg'.
 */
void* handle_dns_request(void* arg);

/**
 * Receives data from a socket with a safety timeout mechanism.
 * * Unlike standard recvfrom(), this function will not block indefinitely.
 * It uses poll() to wait for data availability. If no data arrives within
 * the specified timeout, it returns immediately, preventing server hangs.
 *
 * @param sockfd      The file descriptor of the open socket.
 * @param buf         Buffer to store the received data.
 * @param len         Maximum size of the buffer (in bytes).
 * @param flags       Standard recvfrom flags (usually 0).
 * @param src_addr    Pointer to store the sender's address (IP/Port).
 * @param addrlen     Pointer to the size of the src_addr structure.
 * @param timeout_ms  Maximum time to wait in milliseconds (e.g., 2000 for 2s).
 * * @return Number of bytes received on success.
 * @return -1 if the timeout was reached or a poll error occurred.
 */
ssize_t recv_with_timeout(int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen, 
                        int timeout_ms);

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
