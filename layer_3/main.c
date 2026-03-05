#include "ip_filter.h"
#include <signal.h>

static void handle_signal(int sig)
{
    (void)sig;
    ip_filter_cleanup();
    exit(0);
}

int main(int argc, char *argv[])
{
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    if (load_reputation("../reputation/reputation.txt") < 0)
        return 1;            

    printf("[LAYER_3] Starting IP Reputation Filter\n");
    printf("[LAYER_3] D3FEND: D3-ITF | ATT&CK: T1590\n");

    start_ip_filter();
    return 0;
}
