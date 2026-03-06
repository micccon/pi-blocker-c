#define _POSIX_C_SOURCE 200809L
#include "dns.h"
#include "../../common/blocklist.h"

int main(int argc, char *argv[])
{
	const char *upstream_ip = DNS_DEFAULT_UPSTREAM;
	if (argc > 1) upstream_ip = argv[1];

	printf("[LAYER_7] [DNS] Loading blocklist...\n");
	if (load_blocklist("../../hostnames/blocklist.txt") != 0)
		return 1;

	printf("[LAYER_7] [DNS] Starting DNS proxy server...\n");
	printf("[LAYER_7] [DNS] Upstream DNS: %s\n", upstream_ip);

	start_dns_server(upstream_ip);

	free_blocklist();
	return 0;
}
