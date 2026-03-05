#include "ip_filter.h"
#include <signal.h>

static void handle_signal(int sig)
{
    (void)sig;
    request_ip_filter_stop();
}

int main()
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
