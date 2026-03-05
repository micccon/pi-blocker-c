#include "ip_filter.h"
#include <signal.h>

// --- runtime stop state ---
// set by signal handler path in main.c
static volatile sig_atomic_t g_ip_filter_stop = 0;
static int g_ip_filter_fd = -1;

void request_ip_filter_stop(void)
{
    // --- request main loop shutdown ---
    g_ip_filter_stop = 1;

    // --- close socket to unblock recvfrom() ---
    if (g_ip_filter_fd >= 0)
        close(g_ip_filter_fd);
}

int load_reputation(const char *path)
{
    // --- delegate to common reputation module ---
    return reputation_load(path);
}

int check_ip_reputation(uint32_t src_ip)
{
    // --- delegate to common reputation module ---
    return reputation_match_ip(src_ip);
}

void ip_filter_cleanup()
{
    // --- clear common reputation entries ---
    reputation_cleanup();

    // --- call enforce_cleanup() ---
    enforce_cleanup();

    printf("[LAYER_3] cleanup complete\n");
}

void start_ip_filter()
{
    // --- create raw socket ---
    int raw_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (raw_fd < 0)
    {
        perror("Failed to create raw socket (are you root?)");
        exit(1);
    }

    // --- expose socket to stop-request path ---
    g_ip_filter_fd = raw_fd;
    g_ip_filter_stop = 0;

    printf("[LAYER_3] IP reputation filter active\n");
    printf("[LAYER_3] D3FEND: D3-ITF | ATT&CK: T1590\n");
    printf("[LAYER_3] Loaded %d reputation entries\n", reputation_entry_count());

    while (!g_ip_filter_stop)
    {
        // --- allocate task ---
        ip_task_t *task = calloc(1, sizeof(ip_task_t));
        if (!task) continue;

        // --- recvfrom into task->buffer ---
        socklen_t addr_len = sizeof(task->src_addr);
        task->packet_len = recvfrom(raw_fd, task->buffer, IP_REP_BUFFER_SIZE, 0,
                                    (struct sockaddr *)&task->src_addr, &addr_len);
        if (task->packet_len < 0)
        {
            free(task);
            if (g_ip_filter_stop)
                break;
            continue;
        }

        // --- validate IP header ---
        if (task->packet_len < (int)(sizeof(struct eth_hdr) + sizeof(struct ip_hdr)))
        {
            free(task);
            continue;
        }
        struct ip_hdr *ip_header = (struct ip_hdr *)(task->buffer + sizeof(struct eth_hdr));
        size_t ip_hdr_len = (ip_header->version_ihl & 0x0F) * 4;
        if (ip_hdr_len < 20 || (int)ip_hdr_len > task->packet_len)
        {
            free(task);
            continue;
        }

        // check version == 4
        if ((ip_header->version_ihl >> 4) != 4)
        {
            free(task);
            continue;
        }

        // --- filter out your own traffic ---
        if (ip_header->src_addr == htonl(INADDR_LOOPBACK))
        {
            free(task);
            continue;
        }

        // --- spawn thread ---
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_ip_packet, task) != 0)
        {
            free(task);
            continue;
        }
        pthread_detach(thread_id);
    }

    // --- close raw socket ---
    if (g_ip_filter_fd >= 0)
    {
        close(g_ip_filter_fd);
        g_ip_filter_fd = -1;
    }

    // --- cleanup shared state ---
    ip_filter_cleanup();
}

void *handle_ip_packet(void *arg)
{
    ip_task_t *task = (ip_task_t *)arg;

    // --- extract src_ip ---
    struct ip_hdr *ip_header = (struct ip_hdr *)(task->buffer + sizeof(struct eth_hdr));
    uint32_t src_ip = ip_header->src_addr;  // network byte order

    // --- check reputation ---
    int match = check_ip_reputation(src_ip);

    // --- if match → block and log ---
    if (match)
    {
        block_ip(src_ip);
        log_ip_decision("BLOCKED", task, src_ip);
    }
    else
        log_ip_decision("ALLOWED", task, src_ip);

    free(task);
    return NULL;
}

void log_ip_decision(const char *action, ip_task_t *task,
                     uint32_t src_ip)
{
    // --- timestamp ---
    time_t now = time(NULL);
    struct tm tm_buf;
    char timestamp[32];
    if (localtime_r(&now, &tm_buf) != NULL)
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_buf);
    else
        strncpy(timestamp, "unknown-time", sizeof(timestamp));

    // --- src IP string ---
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr = { .s_addr = src_ip };
    if (inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str)) == NULL)
    {
        strncpy(ip_str, "unknown-ip", sizeof(ip_str));
        ip_str[sizeof(ip_str) - 1] = '\0';
    }

    // --- log line ---
    printf("[%s] [LAYER_3] [IP_REP] [%s] src=%s d3fend=D3-ITF attck=T1590\n",
           timestamp,
           (action != NULL) ? action : "UNKNOWN",
           ip_str);

    (void)task;
}
