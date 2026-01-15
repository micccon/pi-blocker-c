#include <ctype.h>

#include "dns.h"

// Define globals
char **g_blocklist = NULL;
size_t g_blocklist_size = 0;

// ---------- BLOCKLIST MANAGEMENT ----------

// Comparison function to be used to for binary search
// Expects pointers to string pointers (char**)
int compare_strings(const void *a, const void *b)
{
	const char *sa = *(const char **)a;
	const char *sb = *(const char **)b;
	return strcmp(sa, sb);
}

// Frees each entry in the blocklist and the blocklist itself
void free_blocklist()
{
	if (g_blocklist)
	{
		for (size_t i = 0; i < g_blocklist_size; i++)
			free(g_blocklist[i]);
		free(g_blocklist);
	}
}

// Loads text file of domains into memory and prepares them
// Assumes file is already sorted
void load_blocklist(const char *filename)
{
	FILE *file = fopen(filename, "r");
	if (!file)
	{
		perror("Could not open blocklist.txt");
		return;
	}

	// Counts lines to allocate exact memory
	size_t lines = 0;
	char buffer[BLOCKLIST_LINE_BUFFER];
	while ( fgets(buffer, sizeof(buffer), file) )
		lines++;

	rewind(file); // Go back to beginning of file

	// Allocate the main pointer array
	g_blocklist = calloc(lines, sizeof(char*));
	if (!g_blocklist)
	{
		perror("Out of memory loading blocklist");
		exit(1);
	}

	// Read and store each domain
	size_t i = 0;
	while ( fgets(buffer, sizeof(buffer), file) && i < lines)
	{
		// Strip newline character
		buffer[strcspn(buffer, "\r\n")] = 0;

		// Skip any potential empty lines
		if (strlen(buffer) == 0) continue;

		// Allocate ram for this specific string
		if ( (g_blocklist[i] = strdup(buffer)) == NULL )
		{
			fclose(file);
			free_blocklist();
			perror("Failure to allocate memory for specific string");
			exit(1);
		}

		i++;
	}

	fclose(file);
	g_blocklist_size = i;

	// We assume the file is sorted, if you didn't sort externally uncomment this line
	// qsort(g_blocklist, g_blocklist_size, sizeof(char*), compare_strings);

	printf("Blocklist loaded: %zu domains active.\n", g_blocklist_size);
}

// Helper to perform the actual bsearch call
bool check_domain(const char *domain)
{
	if (!g_blocklist || g_blocklist_size == 0) return false;

	// Note: Use 'domain' directly if your compare_strings expects a char*
	void *found = bsearch(&domain, g_blocklist, g_blocklist_size,
		sizeof(char*), compare_strings);
	return (found != NULL);
}

// Checks if the given host is on the blocklist or not
bool is_blocked(char *host)
{
	// Check domain given first
	if ( check_domain(host) ) return true;

	// Walk up the domain tree
	char *dot = strchr(host, '.');
	while (dot != NULL)
	{
		// Move past current dot to next level
		char *parent_domain = dot + 1;

		// Get new dot, if no more dots (e.g ".com") break
		dot = strchr(parent_domain, '.');
		if (!dot) break;

		if ( check_domain(parent_domain) ) return true;
	}
	return false;
}

// ---------- DNS PARSER ----------

// Reads the name of a domain
unsigned char* read_name(unsigned char* reader, unsigned char* buffer, int* count)
{
	// Parameter checks
	if (!reader || !buffer || !count)
	{
		perror("Null / invalid arguments to read_name");
		return NULL;
	}

	// Malloc name buffer
	char *name = (char *)calloc(DNS_NAME_SIZE, 1);
	if (name == NULL)
	{
		perror("Unable to malloc for name in read_name");
		return NULL;
	}

	*count = 0;
	int name_offset = 0;
	int jumped = 0;
	int loop_count = 0; // To prevent malicious continuous jumps

	// Main loop, checks standard end and max count
	while( *reader != 0 && *count < DNS_NAME_SIZE && loop_count < MAX_LOOP_COUNT) // 0 marks end of name
	{
		// Compression check (11xxxxxx / 0xC0)
		if ( (*reader & JUMP_HEX_VALUE) == JUMP_HEX_VALUE )
		{
			// Calculate offset
			// Combine bottom 6 bits of byte 1 with byte 2
			int jump_offset = ( (*reader & FIRST_OFFSET_HEX_VALUE) << 8)
						| *(reader + 1);

			// Count the pointer size if we haven't jumped yet
			if (jumped == 0)
				*count += 2;

			jumped = 1; // Set to "jump mode"

			reader = buffer + jump_offset;
		}
		else // Standard labeling
		{
			unsigned int segment_len = *reader;

			// Prevent buffer overflow
			if (name_offset + segment_len + 1 >= DNS_NAME_SIZE)
			{
				fprintf(stderr, "Error: DNS name too long, truncated.\n");
				free(name);
				return NULL; // Stop reading to protect memory
			}

			// Copy the segment length of letters into the url name
			memcpy(&name[name_offset], reader + 1, segment_len);

			// Update positions
			name_offset += segment_len;
			reader += segment_len + 1;

			// Add the '.'
			name[name_offset] = '.';
			name_offset++;

			// Increment count only if we haven't jumped
			if (jumped == 0)
				*count += segment_len + 1;
		}
		loop_count++;
	}
	// Remove potential trailing dot
	if (name_offset > 0)
		name[name_offset - 1] = '\0';
	else
		name[0] = '\0';

	// Account for the final null byte
	if (jumped == 0) *count += 1;

	return (unsigned char*)name;
}

// ---------- DNS THREAD HANDLING ----------

void* handle_dns_request(void *arg)
{
	// Convert argument into dns_task to access dns request info
	dns_task_t *task = (dns_task_t *)arg;

	// Skip 12-byte dns hdr to get to question section
	unsigned char *reader = task->buffer + sizeof(struct dns_hdr);
	int bytes_read = 0;

	// Use helper to extract domain name
	char *domain_name = (char *)read_name(reader, task->buffer, &bytes_read);

	// Convert domain to lowercase
	for (int i = 0; domain_name[i]; i++)
		domain_name[i] = tolower(domain_name[i]);

	// Refuse packet so client doesn't time out
	if ( is_blocked(domain_name) )
	{
		printf("[BLOCKED] %s requested by %s\n", domain_name,
					inet_ntoa(task->client_addr.sin_addr));

		// Create a "Refused" response
		struct dns_hdr *header = (struct dns_hdr *)task->buffer;
		header->flags = htons(ntohs(header->flags) | DNS_FLAG_QR | 0x0005); // QR=1 (Response), RCODE=5 (Refused)

		// Send the "Refused" header back to the client immediately
		sendto(task->client_socket, task->buffer, task->query_size, 0,
			(struct sockaddr *)&task->client_addr, sizeof(task->client_addr));
	}
	else // Is a normal packet
    {
        printf("[FORWARD] %s requested by %s\n", domain_name,
                    inet_ntoa(task->client_addr.sin_addr));
        
        // Create thread-local upstream socket to avoid race conditions
        int upstream_socket;
        if ( (upstream_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0 )
        {
            perror("Upstream socket failed");
            free(domain_name);
            free(task);
            return NULL;
        }

        // Send the query to the upstream provider (e.g., 8.8.8.8)
        sendto(upstream_socket, task->buffer, task->query_size, 0,
            (struct sockaddr *)&task->upstream_addr,
            sizeof(task->upstream_addr));

        // Use a thread-local buffer to prevent using the global upstream in main
        unsigned char upstream_response[UPSTREAM_BUFFER_SIZE];
        ssize_t response_size = recv_with_timeout(upstream_socket, upstream_response,
            UPSTREAM_BUFFER_SIZE, 0, NULL, NULL, 2000);

        if (response_size > 0)
        {
            // Send the successful response back to the client
            sendto(task->client_socket, upstream_response, response_size, 0,
                (struct sockaddr *)&task->client_addr, sizeof(task->client_addr));
        }
        else
            printf("  [TIMEOUT] Upstream did not reply for %s\n", domain_name);

        // Close local socket
        close(upstream_socket);
    }

    // Final cleanup
    free(domain_name);
    free(task); 
    return NULL;
}

// Receives a request without blocking after a certain period
ssize_t recv_with_timeout(int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen, 
                        int timeout_ms) 
{

	struct pollfd fds[1];
	fds[0].fd = sockfd;
	fds[0].events = POLLIN; // Notify when there is data to read

	// Wait for 'timeout_ms' milliseconds
	int activity = poll(fds, 1, timeout_ms);

	if (activity == 0) // Timeout reached
		return 0;
	else if (activity < 0) // Actual poll error
	{
		perror("Poll error");
		return -1;
	}

	// Data is ready and safe to call recvfrom.
	return recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}