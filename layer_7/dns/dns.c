#include <ctype.h>
#include <time.h>

#include "dns.h"
#include "../../common/blocklist.h"

void start_dns_server(const char *upstream_ip)
{
	// Declare socket
	int client_socket;
	if ( (client_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("Initializing socket failed");
		exit(1);
	}

	// Server socket creation and setup
	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(DNS_PORT);
	server_addr.sin_addr.s_addr = INADDR_ANY;

	// Bind the client socket
	if ( ( bind(client_socket, (const struct sockaddr *)&server_addr,
				sizeof(server_addr)) ) < 0 ) {
		perror("Couldn't bind client socket");
		close(client_socket);
		exit(1);
	}

	// Upstream address (where we forward valid requests)
	struct sockaddr_in upstream_addr;
	memset(&upstream_addr, 0, sizeof(upstream_addr));
	upstream_addr.sin_family = AF_INET;
	upstream_addr.sin_port = htons(DNS_PORT);

	// Convert upstream ip to compact binary
	if (inet_pton(AF_INET, upstream_ip, &upstream_addr.sin_addr) <= 0) {
		perror("Invalid upstream IP address");
		close(client_socket);
		exit(1);
	}

	printf("[LAYER_7] [DNS] Listening on 0.0.0.0:%d\n", DNS_PORT);
	printf("[LAYER_7] [DNS] Waiting for incoming DNS queries...\n");

	// Main loop process
	while(1)
	{
		// Allocate memory for new DNS task
		dns_task_t *task = calloc(1, sizeof(dns_task_t));
		if (!task)
		{
			perror("Calloc failed for DNS task");
			continue; // Keep going on for new requests n that
		}

		task->client_socket = client_socket;
		task->upstream_addr = upstream_addr;
		socklen_t client_addr_len = sizeof(task->client_addr);

		// Receive packet into the task buffer
		task->query_size = recvfrom(client_socket, task->buffer, DNS_BUFFER_SIZE,
			0, (struct sockaddr *)&task->client_addr, &client_addr_len);

		// Drop junk packet
		if (task->query_size < (ssize_t)sizeof(struct dns_hdr))
		{
			free(task);
			continue;
		}

		if (DNS_VERBOSE_RX) {
			printf("Received a %zd-byte packet from %s\n",
				task->query_size, inet_ntoa(task->client_addr.sin_addr));
		}

		// Create new worked thread
		pthread_t thread_id;
		if (pthread_create(&thread_id, NULL, handle_dns_request, task) != 0)
		{
			perror("Failed to create pthread");
			free(task);
		}
		pthread_detach(thread_id);
	}
}

void log_dns_decision(const char *action, const char *domain, const struct sockaddr_in *client_addr)
{
	char timestamp[32];
	time_t now = time(NULL);
	struct tm tm_buf;
	if (localtime_r(&now, &tm_buf) != NULL)
		strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_buf);
	else
		strncpy(timestamp, "unknown-time", sizeof(timestamp));

	char client_ip[INET_ADDRSTRLEN];
	if (client_addr != NULL &&
		inet_ntop(AF_INET, &client_addr->sin_addr, client_ip, sizeof(client_ip)) != NULL)
	{
		/* populated by inet_ntop */
	}
	else
	{
		strncpy(client_ip, "unknown-ip", sizeof(client_ip));
		client_ip[sizeof(client_ip) - 1] = '\0';
	}

	printf("[%s] [LAYER_7] [DNS] [%s] domain=%s client=%s d3fend=D3-DNSDL attck=T1071.004\n",
		timestamp,
		(action != NULL) ? action : "UNKNOWN",
		(domain != NULL) ? domain : "unknown-domain",
		client_ip);
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
		log_dns_decision("BLOCKED", domain_name, &task->client_addr);

		// Create a "Refused" response
		struct dns_hdr *header = (struct dns_hdr *)task->buffer;
		header->flags = htons(ntohs(header->flags) | DNS_FLAG_QR | 0x0005); // QR=1 (Response), RCODE=5 (Refused)

		// Send the "Refused" header back to the client immediately
		sendto(task->client_socket, task->buffer, task->query_size, 0,
			(struct sockaddr *)&task->client_addr, sizeof(task->client_addr));
	}
	else // Is a normal packet
    {
        log_dns_decision("FORWARD", domain_name, &task->client_addr);
        
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
            log_dns_decision("TIMEOUT", domain_name, &task->client_addr);

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
