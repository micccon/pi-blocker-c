#define _POSIX_C_SOURCE 200809L
#include "dns.h"

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

	// Upstream address (where we forward valid requests)
	struct sockaddr_in upstream_addr;
	memset(&upstream_addr, 0, sizeof(upstream_addr));
	upstream_addr.sin_family = AF_INET;
	upstream_addr.sin_port = htons(DNS_PORT);

	// Convert upstream ip to compact binary
	if (inet_pton(AF_INET, upstream_ip, &upstream_addr.sin_addr) <= 0) {
		perror("Invalid upstream IP address");
		exit(1);
	}

	printf("Pi-Blocker is listening on 0.0.0.0:%d (All Interfaces)\n", DNS_PORT);
	printf("Waiting for incoming DNS queries...\n");

	// Main loop process
	while(1) 
	{
		// Allocate memory for new DNS task
		dns_task_t *task = calloc(sizeof(dns_task_t), 1);
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

		printf("Received a %zd-byte packet from %s\n",
			task->query_size, inet_ntoa(task->client_addr.sin_addr));
		
		// Create new worked thread
		pthread_t thread_id;
		if (pthread_create(&thread_id, NULL, handle_dns_request, task) == 0)
			pthread_detach(thread_id);
		else
		{
			perror("Failed to create pthread");
			free(task);
		}
	}
	// Final cleanup
	free_blocklist();
	close(client_socket);
	return 0;
}
