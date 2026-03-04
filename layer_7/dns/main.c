#define _POSIX_C_SOURCE 200809L
#include "dns.h"
#include "../../common/blocklist.h"

int main(int argc, char *argv[])
{
	const char *upstream_ip = DNS_DEFAULT_UPSTREAM;
	if (argc > 1) upstream_ip = argv[1];

	printf("Loading blocklist...\n");
	if (load_blocklist("../../hostnames/blocklist.txt") != 0)
		return 1;

	printf("Starting DNS Proxy Server...\n");
	printf("Upstream DNS: %s\n", upstream_ip);

	start_dns_server(upstream_ip);

	free_blocklist();
	return 0;
}
