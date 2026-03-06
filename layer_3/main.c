#include "ip_filter.h"
#include <signal.h>

static void handle_signal(int sig)
{
    (void)sig;
    request_ip_filter_stop();
}

int main(int argc, char *argv[])
{
    bool verbose = false;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-v") == 0)
            verbose = true;
        else
        {
            fprintf(stderr, "Usage: %s [-v]\n", argv[0]);
            return 1;
        }
    }

    ip_filter_set_verbose(verbose);

    if (load_reputation("../reputation/reputation.txt") < 0)
        return 1;            

    printf("[LAYER_3] Starting IP Reputation Filter\n");
    printf("[LAYER_3] D3FEND: D3-ITF | ATT&CK: T1590\n");

    start_ip_filter();
    return 0;
}
