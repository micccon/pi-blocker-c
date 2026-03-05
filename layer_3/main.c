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

    const char *rep_file = (argc > 1) ? argv[1] : IP_REP_FILE;
    if (argc <= 1 && access(rep_file, R_OK) != 0)
        rep_file = "reputation/reputation.txt";

    int count = load_reputation(rep_file);
    if (count < 0)
    {
        fprintf(stderr, "[LAYER_3] Failed to load reputation file: %s\n", rep_file);
        return 1;
    }

    printf("[LAYER_3] Starting IP Reputation Filter\n");
    printf("[LAYER_3] D3FEND: D3-ITF | ATT&CK: T1590\n");

    start_ip_filter();
    return 0;
}
