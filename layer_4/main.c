#include "filter.h"
#include "../common/enforce.h"
#include "../common/net_hdrs.h"
#include <signal.h>

static void handle_signal(int sig)
{
    (void)sig;
    enforce_cleanup();
    exit(0);
}

int main(void)
{
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("[LAYER_4] Starting Port Filter\n");
    printf("[LAYER_4] Implementing D3FEND technique: D3-NTCD\n");

    start_port_filter();
    return 0;
}