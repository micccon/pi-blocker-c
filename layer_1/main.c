#include "link_monitor.h"
#include <signal.h>

static void handle_signal(int sig)
{
    (void)sig;
    _exit(0);
}

int main(void)
{
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("[LAYER_1] Starting Physical Layer Monitor\n");
    printf("[LAYER_1] D3FEND: D3-NTA | ATT&CK: T1200\n");

    start_link_monitor();
    return 0;
}
