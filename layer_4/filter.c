#include "filter.h"
#include <signal.h>

// --- global scan table ---
static port_scan_table_t g_scan_table;
static volatile sig_atomic_t g_port_filter_stop = 0;
static int g_port_filter_fd = -1;

void request_port_filter_stop(void)
{
    // --- request main loop shutdown ---
    g_port_filter_stop = 1;

    // --- close socket to unblock recvfrom() ---
    if (g_port_filter_fd >= 0)
        close(g_port_filter_fd);
}

// --- internal hash function ---
static uint32_t hash_ip(uint32_t ip)
{
    return ip % PORT_SCAN_TABLE_SIZE;  // simple modulo hash on source IP
}

// caller must hold table->lock
static void port_scan_prune_expired_locked(port_scan_table_t *table, time_t now)
{
    for (int i = 0; i < PORT_SCAN_TABLE_SIZE; i++)
    {
        port_scan_entry_t **cursor = &table->buckets[i];
        while (*cursor != NULL)
        {
            port_scan_entry_t *entry = *cursor;
            if (now - entry->window_start > PORT_SCAN_WINDOW_SECONDS)
            {
                *cursor = entry->next;
                free(entry);
                table->total_entries--;
            }
            else
                cursor = &entry->next;
        }
    }
}


// ============================================================
// port_scan_table_init
// ============================================================

void port_scan_table_init(port_scan_table_t *table)
{
    // --- zero all buckets, set total_entries to 0, init mutex ---
    memset(table->buckets, 0, sizeof(table->buckets));
    table->total_entries = 0;                          
    int result = pthread_mutex_init(&table->lock, NULL);

    if (result != 0)
    {
        fprintf(stderr, "Failed to initialize port scan table mutex: %s\n", strerror(result));
        exit(1);
    }
}

port_scan_entry_t *port_scan_lookup(port_scan_table_t *table, uint32_t src_ip)
{
    int index = hash_ip(src_ip);
    port_scan_entry_t *entry = table->buckets[index];
    while (entry != NULL)
    {
        if (entry->src_ip == src_ip)
            return entry;

        entry = entry->next;
    }
    return NULL;  // not found
}


// ============================================================
// port_scan_insert
// caller must hold table->lock
// ============================================================

port_scan_entry_t *port_scan_insert(port_scan_table_t *table, uint32_t src_ip)
{
    time_t now = time(NULL);

    // check if table is full
    if (table->total_entries >= PORT_SCAN_MAX_ENTRIES)
    {
        port_scan_prune_expired_locked(table, now);

        // still full after pruning
        if (table->total_entries >= PORT_SCAN_MAX_ENTRIES)
            return NULL;
    }
    port_scan_entry_t *entry = calloc(1, sizeof(port_scan_entry_t));
    if (!entry) return NULL;

    // -- fill in entry fields:
    entry->src_ip       = src_ip;
    entry->port_index   = 0;
    entry->unique_ports = 0;
    entry->window_start = now;
    entry->flagged      = false;
    entry->next         = NULL;

    // insert at HEAD of bucket chain
    int index = hash_ip(src_ip);
    entry->next = table->buckets[index];
    table->buckets[index] = entry;
    table->total_entries++;
    return entry;
}

// ============================================================
// check_port_scan
// main detection logic
// returns +unique_ports (normal), -unique_ports (scan detected)
//
// unique port counting uses the circular buffer:
//   before writing new port to buffer, check if it already
//   exists in ports_seen[] — if yes, don't increment unique_ports
//   if no, add it, increment unique_ports
//
// same signed return convention as check_syn_flood() in Layer 5
// ============================================================

int check_port_scan(port_scan_table_t *table, uint32_t src_ip, uint16_t dst_port)
{
    time_t now = time(NULL);

    // --- acquire lock ---
    pthread_mutex_lock(&table->lock);

    // --- lookup or insert ---
    port_scan_entry_t *entry = port_scan_lookup(table, src_ip);
    if (!entry)
        entry = port_scan_insert(table, src_ip);

    if (!entry)
    {
        pthread_mutex_unlock(&table->lock);
        return 0;
    }


    // --- reset window if expired ---
    if (now - entry->window_start > PORT_SCAN_WINDOW_SECONDS)
    {
        memset(entry->ports_seen, 0, sizeof(entry->ports_seen));
        entry->port_index   = 0;
        entry->unique_ports = 0;
        entry->window_start = now;
        entry->flagged      = false;
    }

    // --- check if dst_port already in circular buffer ---
    bool port_already_seen = false;
    for (int i = 0; i < PORT_HISTORY_SIZE; i++)
    {
        if (entry->ports_seen[i] == dst_port)
        {
            port_already_seen = true;
            break;
        }
    }

    // --- if new port — add to circular buffer and increment unique_ports ---
    entry->ports_seen[entry->port_index % PORT_HISTORY_SIZE] = dst_port;
    entry->port_index++;
    if (!port_already_seen)
        entry->unique_ports++;

    // --- check threshold ---
    if (entry->unique_ports > PORT_SCAN_THRESHOLD)
    {
        if (!entry->flagged)
        {
            entry->flagged = true;
            int first_block_count = entry->unique_ports;
            pthread_mutex_unlock(&table->lock);
            return -first_block_count;  // first transition to blocked
        }
    }

    int unique_ports = entry->unique_ports;
    pthread_mutex_unlock(&table->lock);
    return unique_ports;  // allowed or already flagged
}

void port_scan_table_cleanup(port_scan_table_t *table)
{
    pthread_mutex_lock(&table->lock);

    // --- walk every bucket ---
    for (int i = 0; i < PORT_SCAN_TABLE_SIZE; i++)
    {
        port_scan_entry_t *entry = table->buckets[i];
        while (entry != NULL)
        {
            port_scan_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
        table->buckets[i] = NULL;
    }
    table->total_entries = 0;
    pthread_mutex_unlock(&table->lock);
    pthread_mutex_destroy(&table->lock);
}


// ============================================================
// start_port_filter
// ============================================================

void start_port_filter()
{
    // --- initialize scan table ---
    port_scan_table_init(&g_scan_table);

    // --- create raw socket ---
    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_fd < 0)
    {
        perror("Failed to create raw socket (are you root?)");
        exit(1);
    }

    // --- expose socket to stop-request path ---
    g_port_filter_fd = raw_fd;
    g_port_filter_stop = 0;

    printf("[LAYER_4] Port filter listening on all interfaces\n");
    printf("[LAYER_4] D3FEND: D3-NTCD | ATT&CK: T1046\n");
    printf("[LAYER_4] Threshold: %d unique ports per %d seconds\n",
           PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW_SECONDS);

    while (!g_port_filter_stop)
    {
        // --- allocate task ---
        port_task_t *task = calloc(1, sizeof(port_task_t));
        if (!task) continue;

        // --- receive raw packet ---
        socklen_t addr_len = sizeof(task->src_addr);
        task->packet_len = recvfrom(raw_fd, task->buffer, PORT_BUFFER_SIZE,
                                    0, (struct sockaddr *)&task->src_addr, &addr_len);
        if (task->packet_len < 0)
        {
            free(task);
            if (g_port_filter_stop)
                break;
            continue;
        }

        // --- validate and parse IP header ---
        if (task->packet_len < (int)sizeof(struct ip_hdr))
        {
            free(task);
            continue;
        }

        struct ip_hdr *ip_header = (struct ip_hdr *)task->buffer;
        size_t ip_hdr_len = (ip_header->version_ihl & 0x0F) * 4;
        if (ip_hdr_len < 20 || (int)ip_hdr_len > task->packet_len)
        {
            free(task);
            continue;
        }

        // --- filter TCP only ---
        if (ip_header->protocol != IPPROTO_TCP)
        {
            free(task);
            continue;
        }

        // --- ensure minimal TCP header is present ---
        if (task->packet_len < (int)(ip_hdr_len + sizeof(struct tcp_hdr)))
        {
            free(task);
            continue;
        }

        struct tcp_hdr *tcp_header = (struct tcp_hdr *)(task->buffer + ip_hdr_len);
        size_t tcp_hdr_len = ((tcp_header->data_offset & 0xF0) >> 4) * 4;
        if (tcp_hdr_len < 20 || task->packet_len < (int)(ip_hdr_len + tcp_hdr_len))
        {
            free(task);
            continue;
        }

        // --- detect scan type from flags ---
        uint8_t flags = tcp_header->flags;
        bool is_syn = (flags & TCP_FLAG_SYN) && !(flags & TCP_FLAG_ACK);
        bool is_null = (flags == TCP_FLAGS_NULL);
        bool is_xmas = (flags == TCP_FLAGS_XMAS);
        bool is_fin  = (flags == TCP_FLAG_FIN) && !(flags & TCP_FLAG_ACK); 
        if (!is_syn && !is_null && !is_xmas && !is_fin)
        {
            free(task);
            continue;
        }

        // --- store raw socket for worker-side rst injection ---
        task->raw_fd = raw_fd;

        // --- spawn thread ---
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_port_packet, task) != 0)
        {
            free(task);
            continue;
        }
        pthread_detach(thread_id);
    }

    // --- close raw socket ---
    if (g_port_filter_fd >= 0)
    {
        close(g_port_filter_fd);
        g_port_filter_fd = -1;
    }

    // --- cleanup detector table and enforcement state ---
    port_scan_table_cleanup(&g_scan_table);
    enforce_cleanup();
    printf("[LAYER_4] cleanup complete\n");
}


// ============================================================
// handle_port_packet
// thread entry point
// ============================================================

void *handle_port_packet(void *arg)
{
    port_task_t *task = (port_task_t *)arg;

    // --- extract src_ip and dst_port from packet ---
    if (task->packet_len < (int)sizeof(struct ip_hdr))
    {
        free(task);
        return NULL;
    }

    struct ip_hdr *ip_header = (struct ip_hdr *)task->buffer;
    uint32_t src_ip = ip_header->src_addr;  // keep in network byte order
    size_t ip_hdr_len = (ip_header->version_ihl & 0x0F) * 4;
    if (ip_hdr_len < 20 || (int)ip_hdr_len > task->packet_len)
    {
        free(task);
        return NULL;
    }

    if (task->packet_len < (int)(ip_hdr_len + sizeof(struct tcp_hdr)))
    {
        free(task);
        return NULL;
    }

    struct tcp_hdr *tcp_header = (struct tcp_hdr *)(task->buffer + ip_hdr_len);
    size_t tcp_hdr_len = ((tcp_header->data_offset & 0xF0) >> 4) * 4;
    if (tcp_hdr_len < 20 || task->packet_len < (int)(ip_hdr_len + tcp_hdr_len))
    {
        free(task);
        return NULL;
    }

    uint16_t dst_port = ntohs(tcp_header->dst_port);

    // --- call check_port_scan ---
    int count = check_port_scan(&g_scan_table, src_ip, dst_port);

    // --- scan detected (count < 0) ---
    if (count < 0)
    {
        block_ip(src_ip);

        int payload_len = task->packet_len - (int)ip_hdr_len - (int)tcp_hdr_len;
        if (payload_len < 0) payload_len = 0;
        uint32_t rst_ack_nbo = htonl(ntohl(tcp_header->seq_num) + (uint32_t)payload_len);

        rst_inject(task->raw_fd, src_ip, ntohs(tcp_header->src_port),
                   ip_header->dst_addr, dst_port, rst_ack_nbo);
        log_port_decision("BLOCKED", task, src_ip, dst_port, -count);
    }
    else if (count > PORT_SCAN_THRESHOLD)
    {
        // already flagged — avoid repeated block/rst calls
        log_port_decision("BLOCKED", task, src_ip, dst_port, count);
    }
    else
    {
        // --- normal traffic (count >= 0) ---
        log_port_decision("ALLOWED", task, src_ip, dst_port, count);
    }

    free(task);
    return NULL;
}


// ============================================================
// log_port_decision
// ============================================================

void log_port_decision(const char *action, port_task_t *task,
                       uint32_t src_ip, uint16_t dst_port, int unique_ports)
{
    time_t now = time(NULL);
    struct tm tm_buf;
    char timestamp[32];
    if (localtime_r(&now, &tm_buf) != NULL)
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_buf);
    else
        strncpy(timestamp, "unknown-time", sizeof(timestamp));

    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr = { .s_addr = src_ip };
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

    printf("[%s] [LAYER_4] [PORT] [%s] src=%s dst_port=%d unique_ports=%d "
           "d3fend=D3-NTCD attck=T1046\n",
           timestamp, action, ip_str, dst_port, unique_ports);

    (void)task;
}
