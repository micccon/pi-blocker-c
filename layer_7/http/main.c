#define _POSIX_C_SOURCE 200809L

#include "proxy.h"
#include "../dns/dns.h"  // for blocklist functions and is_blocked()

int main(int argc, char *argv[])
{
    // --- load the blocklist ---
    load_blocklist("../dns/hostnames/blocklist.txt");

    printf("HTTP Proxy Server is starting...\n");
    printf("Listening on port 8080\n");

    // --- start the proxy ---
    start_proxy_server();

    // --- cleanup ---
    free_blocklist();

    return 0;
}