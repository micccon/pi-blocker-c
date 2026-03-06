#define _POSIX_C_SOURCE 200809L

#include "proxy.h"
#include "../../common/blocklist.h"

int main(void)
{
    // --- load the blocklist ---
    printf("[LAYER_7] [HTTP] Loading blocklist...\n");
    if (load_blocklist("../../hostnames/blocklist.txt") != 0)
        return 1;

    printf("[LAYER_7] [HTTP] Starting HTTP proxy server...\n");

    // --- start the proxy ---
    start_proxy_server();

    // --- cleanup ---
    free_blocklist();

    return 0;
}
