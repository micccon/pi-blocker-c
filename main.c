#define _POSIX_C_SOURCE 200809L // Enable POSIX features like strdup
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <ctype.h>

#include "dns.h"

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

int main(int argc, char *argv[])
{

	// Parse potential args
	char *upstream_ip = "8.8.8.8";
	if (argc > 1) upstream_ip = argv[1];

	// Load blocklist
	printf("Loading blocklist...\n");
	load_blocklist("hostnames/blocklist.txt");

	printf("Starting DNS Proxy Server...\n");
	printf("Forwarding non-blocked queries to: %s\n", upstream_ip);

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

	// Setup upstream socket
	int upstream_socket;
	if ( (upstream_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0 )
	{
		perror("Upstream socket failed");
		exit(1);
	}

	// Upstream address (where we forward valid requests)
	struct sockaddr_in upstream_addr;
	memset(&upstream_addr, 0, sizeof(upstream_addr));
	upstream_addr.sin_family = AF_INET;
	upstream_addr.sin_port = htons(53); // Standard DNS Port

	// Convert upstream ip to compact binary
	if (inet_pton(AF_INET, upstream_ip, &upstream_addr.sin_addr) <= 0) {
		perror("Invalid upstream IP address");
		exit(1);
	}

	printf("Pi-Blocker is listening on 0.0.0.0:%d (All Interfaces)\n", DNS_PORT);
	printf("Waiting for incoming DNS queries...\n");

	// Vars for the main loop
	unsigned char buffer[DNS_BUFFER_SIZE];
	unsigned char upstream_buffer[UPSTREAM_BUFFER_SIZE];
	struct sockaddr_in client_addr;
	socklen_t client_addr_len = sizeof(client_addr);

	// Main loop, the process goes as follows:
	// 1. Block and wait to receive a request from the client
	// 2. Parse the domain using read_name
	// 3. Check the blocklist using is_blocked
	// 4. Forward to upstream domain
	// 5. Wait for reply
	// 6. Send reply back to client
	while(1) {
		// --- Step 1 ---
		ssize_t query_size = recvfrom(client_socket, buffer, DNS_BUFFER_SIZE,
			0, (struct sockaddr *)&client_addr, &client_addr_len);

		// Drop junk packet
		if (query_size < (ssize_t)sizeof(struct dns_hdr)) continue; 
		printf("Received a %zd-byte packet from %s\n",
			query_size, inet_ntoa(client_addr.sin_addr));

		// --- Step 2 ---
		// Skip 12-byte dns hdr to get to question section
		unsigned char *reader = buffer + sizeof(struct dns_hdr);
		int bytes_read = 0;

		// Use helper to extract domain name
		char *domain_name = (char *)read_name(reader, buffer, &bytes_read);

		if (!domain_name)
		{
			fprintf(stderr, "Failed to parse domain name. Dropping.\n");
			continue;
		}

		// Convert domain to lowercase
		for (int i = 0; domain_name[i]; i++)
			domain_name[i] = tolower(domain_name[i]);

		// --- Step 3 ---
		// Silently drop packet so client doesn't time out
		if ( is_blocked(domain_name) )
		{
			printf("[BLOCKED] %s requested by %s\n", domain_name,
						inet_ntoa(client_addr.sin_addr));

			// Create a "Refused" response
			struct dns_hdr *header = (struct dns_hdr *)buffer;
			header->flags = htons(ntohs(header->flags) | DNS_FLAG_QR | 0x0005); // QR=1 (Response), RCODE=5 (Refused)

			// Send the "Refused" header back to the client immediately
			sendto(client_socket, buffer, query_size, 0, (struct sockaddr *)&client_addr, client_addr_len);
		}
		else
		{
			printf("[FORWARD] %s requested by %s\n", domain_name,
						inet_ntoa(client_addr.sin_addr));

			// --- Step 4 ---
			sendto(upstream_socket, buffer, query_size, 0,
				(struct sockaddr *)&upstream_addr, sizeof(upstream_addr));

			// --- Step 5 ---
			// We use recv_with_timeout here so it isn't blocking traffic
			ssize_t response_size = recv_with_timeout(upstream_socket, upstream_buffer,
				UPSTREAM_BUFFER_SIZE, 0, NULL, NULL, 2000);

			// -- Step 6 ---
			if (response_size > 0)
			{
				sendto(client_socket, upstream_buffer, response_size, 0,
					(struct sockaddr *)&client_addr, client_addr_len);
			}
			else
				printf("  [TIMEOUT] Upstream %s did not reply.\n", upstream_ip);
		}
		// Cleanup memory for this request
		free(domain_name);
	}

	// Final cleanup
	free_blocklist();
	close(client_socket);
	close(upstream_socket);

	return 0;
}
