#define _POSIX_C_SOURCE 200809L

#include "session.h"
#include "../common/blocklist.h"

int main(void)
{
    // --- load blocklist ---
    if (load_blocklist("../hostnames/blocklist.txt") != 0)
        return 1;

    // --- print startup info ---
    printf("[LAYER_5] Starting Session Inspector\n");
    printf("[LAYER_5] Implementing D3FEND technique: D3-CSLL\n");

    // --- start inspector ---
    start_session_tracker();

    // --- cleanup ---
    free_blocklist();

    return 0;
}
