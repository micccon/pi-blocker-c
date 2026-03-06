#include "arp_monitor.h"
#include "../common/net_hdrs.h"
#include <signal.h>

static void handle_signal(int sig)
{
    (void)sig;
    _exit(0);
}

int main()
{
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("[LAYER_2] Starting ARP Monitor\n");
    printf("[LAYER_2] D3FEND: D3-ITF | ATT&CK: T1590\n");

    start_arp_monitor();
    return 0;
}
