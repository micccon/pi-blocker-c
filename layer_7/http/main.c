#define _POSIX_C_SOURCE 200809L

#include "proxy.h"
#include "../../common/blocklist.h"

int main(void)
{
    // --- load the blocklist ---
    if (load_blocklist("../../hostnames/blocklist.txt") != 0)
        return 1;

    printf("HTTP Proxy Server is starting...\n");
    printf("Listening on port 8080\n");

    // --- start the proxy ---
    start_proxy_server();

    // --- cleanup ---
    free_blocklist();

    return 0;
}
