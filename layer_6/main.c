#define _POSIX_C_SOURCE 200809L

#include "tls_inspector.h"
#include "../layer_7/dns/dns.h"  // for blocklist functions and is_blocked()

int main(void)
{
    // --- load blocklist ---
    load_blocklist("../hostnames/blocklist.txt");

    // --- print startup info ---
    printf("[LAYER_6] Starting TLS Inspector on port 443\n");
    printf("[LAYER_6] Implementing D3FEND technique: D3-TLSIC\n");

    // --- start inspector ---
    start_tls_inspector();

    // --- cleanup ---
    free_blocklist();

    return 0;
}
