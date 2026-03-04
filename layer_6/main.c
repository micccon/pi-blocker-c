#define _POSIX_C_SOURCE 200809L

#include "tls_inspector.h"
#include "../common/blocklist.h"

int main(void)
{
    // --- load blocklist ---
    if (load_blocklist("../hostnames/blocklist.txt") != 0)
        return 1;

    // --- print startup info ---
    printf("[LAYER_6] Starting TLS Inspector on port 443\n");
    printf("[LAYER_6] Implementing D3FEND technique: D3-TLSIC\n");

    // --- start inspector ---
    start_tls_inspector();

    // --- cleanup ---
    free_blocklist();

    return 0;
}
