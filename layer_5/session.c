#include "session.h"

// --- global session table ---
// all threads share this one table
// access protected by table->lock
static session_table_t g_session_table;

// --- internal hash function ---
// hashes source/destination tuple to a bucket index
// keep this static — internal detail only
static uint32_t hash_session_key(uint32_t src_ip, uint32_t dst_ip, uint16_t dst_port)
{
    uint32_t src = ntohl(src_ip);
    uint32_t dst = ntohl(dst_ip);
    uint32_t port = (uint32_t)ntohs(dst_port);
    uint32_t mixed = src ^
                     (dst * SESSION_HASH_DST_MULTIPLIER) ^
                     (port * SESSION_HASH_PORT_MULTIPLIER);
    return mixed % SESSION_TABLE_SIZE;
}

void session_table_init(session_table_t *table)
{
    // --- zero all buckets ---
    memset(table->buckets, 0, sizeof(table->buckets));

    // --- initialize total_entries counter ---
    table->total_entries = 0;

    // --- initialize mutex ---
    int result = pthread_mutex_init(&table->lock, NULL);
    if (result != 0)
    {
        fprintf(stderr, "Failed to initialize session table mutex: %s\n", strerror(result));
        exit(1);
    }
}

session_entry_t *session_lookup(session_table_t *table, uint32_t src_ip,
                                uint32_t dst_ip, uint16_t dst_port)
{
    // --- hash tuple to get bucket index ---
    int index = hash_session_key(src_ip, dst_ip, dst_port);

    // --- walk the chain at that bucket ---
    session_entry_t *entry = table->buckets[index];
    while (entry != NULL)
    {
        if (entry->src_ip == src_ip &&
            entry->dst_ip == dst_ip &&
            entry->dst_port == dst_port)
            return entry;

        entry = entry->next;
    }
    return NULL;
}

// caller must hold table->lock
static void session_prune_expired_locked(session_table_t *table, time_t now)
{
    for (int i = 0; i < SESSION_TABLE_SIZE; i++)
    {
        session_entry_t **cursor = &table->buckets[i];
        while (*cursor != NULL)
        {
            session_entry_t *entry = *cursor;
            if (now - entry->window_start > SESSION_WINDOW_SECONDS)
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

session_entry_t *session_insert(session_table_t *table, uint32_t src_ip,
                                uint32_t dst_ip, uint16_t dst_port)
{
    // --- check if table is full ---
    if (table->total_entries >= SESSION_MAX_ENTRIES)
    {
        session_prune_expired_locked(table, time(NULL));

        // still full after pruning
        if (table->total_entries >= SESSION_MAX_ENTRIES)
            return NULL;
    }

    // --- allocate new entry ---
    session_entry_t *entry = calloc(1, sizeof(session_entry_t));
    if (!entry) return NULL;

    // --- fill in entry fields ---
    entry->src_ip       = src_ip;
    entry->dst_ip       = dst_ip;
    entry->dst_port     = dst_port;
    entry->syn_count    = 0;
    entry->window_start = time(NULL);
    entry->blocked      = false;
    entry->next         = NULL;

    // --- insert at HEAD of bucket chain ---
    int index = hash_session_key(src_ip, dst_ip, dst_port);
    entry->next = table->buckets[index];
    table->buckets[index] = entry;

    // --- increment total_entries ---
    table->total_entries++;

    return entry;
}

// returns:
//   -entry->syn_count  → flood detected (caller uses abs value for display)
//    entry->syn_count  → allowed (always >= 1 due to syn_count++)
//    >SESSION_SYN_THRESHOLD (positive) → already blocked, no new enforce needed
//    0                 → insert failed, treat as allowed
int check_syn_flood(session_table_t *table, uint32_t src_ip,
                    uint32_t dst_ip, uint16_t dst_port)
{
    // --- acquire lock ---
    pthread_mutex_lock(&table->lock);

    // --- look up entry ---
    session_entry_t *entry = session_lookup(table, src_ip, dst_ip, dst_port);

    // --- if not found, insert new entry ---
    if (!entry)
        entry = session_insert(table, src_ip, dst_ip, dst_port);

    // insert failed — table full or alloc failure
    // return 0 so caller treats as allowed, avoids false positives
    if (!entry)
    {
        pthread_mutex_unlock(&table->lock);
        return 0;
    }

    // --- check if window has expired ---
    if (time(NULL) - entry->window_start > SESSION_WINDOW_SECONDS)
    {
        entry->syn_count    = 0;
        entry->window_start = time(NULL);
        entry->blocked      = false;
    }

    // --- increment SYN counter ---
    entry->syn_count++;

    // --- check threshold ---
    if (entry->syn_count > SESSION_SYN_THRESHOLD)
    {
        if (!entry->blocked)
        {
            entry->blocked = true;
            pthread_mutex_unlock(&table->lock);
            return -(entry->syn_count);  // first transition to blocked
        }

        pthread_mutex_unlock(&table->lock);
        return entry->syn_count;      // already blocked
    }

    // --- release lock ---
    pthread_mutex_unlock(&table->lock);
    return entry->syn_count;
}

void session_table_cleanup(session_table_t *table)
{
    // WARNING: call only after packet capture is stopped and worker threads are drained.
    // Detached workers calling check_syn_flood() during destroy would race this mutex.
    // --- acquire lock ---
    pthread_mutex_lock(&table->lock);

    // --- walk every bucket ---
    for (int i = 0; i < SESSION_TABLE_SIZE; i++)
    {
        session_entry_t *entry = table->buckets[i];
        while (entry != NULL)
        {
            session_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
        table->buckets[i] = NULL;
    }
    
    // --- reset total_entries ---
    table->total_entries = 0;

    // --- release lock ---
    pthread_mutex_unlock(&table->lock);

    // --- destroy mutex ---
    pthread_mutex_destroy(&table->lock);
}

void start_session_tracker()
{
    // --- initialize session table ---
    session_table_init(&g_session_table);

    // --- create raw socket ---
    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_fd < 0)
    {
        perror("Failed to create raw socket (are you root?)");
        exit(1);
    }

    printf("[LAYER_5] Session tracker listening on all interfaces\n");
    printf("[LAYER_5] D3FEND: D3-CSLL | ATT&CK: T1499\n");
    printf("[LAYER_5] Threshold: %d SYNs per %d seconds\n",
           SESSION_SYN_THRESHOLD, SESSION_WINDOW_SECONDS);

    while (1)
    {
        // --- allocate task ---
        session_task_t *task = calloc(1, sizeof(session_task_t));
        if (!task) continue;

        // --- receive raw packet ---
        socklen_t addr_len = sizeof(task->src_addr);
        task->packet_len = recvfrom(raw_fd, task->buffer, SESSION_BUFFER_SIZE,
                                    0, (struct sockaddr *)&task->src_addr, &addr_len);
        if (task->packet_len < 0)
        {
            free(task);
            continue;
        }

        // --- validate IP header ---
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

        // filter SYN only — not SYN+ACK
        // SYN = 0x02, ACK = 0x10
        // pure SYN: SYN bit set, ACK bit clear
        if (task->packet_len < (int)(ip_hdr_len + sizeof(struct tcp_hdr)))
        {
            free(task);
            continue;
        }

        struct tcp_hdr *tcp_header = (struct tcp_hdr *)(task->buffer + ip_hdr_len);

        size_t tcp_hdr_len = ((tcp_header->data_offset & 0xF0) >> 4) * 4;
        if (tcp_hdr_len < 20 || (int)(ip_hdr_len + tcp_hdr_len) > task->packet_len)
        {
            free(task);
            continue;
        }

        if ((tcp_header->flags & 0x02) != 0x02 || (tcp_header->flags & 0x10) != 0)
        {
            free(task);
            continue;
        }

        // --- spawn thread ---
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_session_packet, task) != 0)
        {
            free(task);
            continue;
        }
        pthread_detach(thread_id);
    }
}

void *handle_session_packet(void *arg)
{
    session_task_t *task = (session_task_t *)arg;

    // --- extract tuple from packet headers ---
    struct ip_hdr *ip_header = (struct ip_hdr *)task->buffer;
    uint32_t src_ip = ip_header->src_addr;  // keep network byte order throughout
    uint32_t dst_ip = ip_header->dst_addr;
    size_t ip_hdr_len = (ip_header->version_ihl & 0x0F) * 4;
    struct tcp_hdr *tcp_header = (struct tcp_hdr *)(task->buffer + ip_hdr_len);
    uint16_t dst_port = tcp_header->dst_port;

    // --- call check_syn_flood ---
    //   negative - flood, abs value = syn_count
    //   positive - allowed, value = syn_count
    //   zero     insert failed, treat as allowed
    int count = check_syn_flood(&g_session_table, src_ip, dst_ip, dst_port);

    if (count < 0)
    {
        // first transition to blocked
        session_enforce_block(src_ip);
        log_session_decision("BLOCKED", task, src_ip, -count);
    }
    else if (count > SESSION_SYN_THRESHOLD)
    {
        // still blocked; avoid repeated enforce calls
        log_session_decision("BLOCKED", task, src_ip, count);
    }
    else
    {
        // allowed or insert failed
        log_session_decision("ALLOWED", task, src_ip, count);
    }

    // --- cleanup ---
    free(task);
    return NULL;
}

void session_enforce_block(uint32_t src_ip)
{
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr = { .s_addr = src_ip };
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
    printf("[LAYER_5] [ENFORCE] would block %s\n", ip_str);
}

void log_session_decision(const char *action, session_task_t *task,
                          uint32_t src_ip, int syn_count)
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
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

    // --- print log line ---'
    printf("[%s] [LAYER_5] [SESSION] [%s] src=%s syn_count=%d d3fend=D3-CSLL attck=T1499\n",
           timestamp, action, ip_str, syn_count);

    // suppress unused parameter warning — task available for future use
    (void)task;
}
