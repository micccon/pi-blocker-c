// link_monitor.c

#include "link_monitor.h"

// --- global link table ---
static link_table_t g_link_table;

// --- state name helper ---
static const char *state_name(link_state_t state)
{
    switch (state)
    {
        case LINK_STATE_UP:       return "UP";
        case LINK_STATE_DOWN:     return "DOWN";
        case LINK_STATE_DISABLED: return "DISABLED";
        default:                  return "UNKNOWN";
    }
}

// --- hash function ---
static uint32_t hash_ifindex(int ifindex)
{
    return (uint32_t)ifindex % LINK_TABLE_SIZE;
}


// ============================================================
// link_table_init
// ============================================================

void link_table_init(link_table_t *table)
{
    memset(table->buckets, 0, sizeof(table->buckets));
    table->total_entries = 0;

    int result = pthread_mutex_init(&table->lock, NULL);
    if (result != 0)
    {
        fprintf(stderr, "Failed to initialize link table mutex\n");
        exit(1);
    }
}


// ============================================================
// link_lookup
// caller must hold table->lock
// ============================================================

link_entry_t *link_lookup(link_table_t *table, int ifindex)
{
    uint32_t index = hash_ifindex(ifindex);
    link_entry_t *entry = table->buckets[index];
    while (entry)
    {
        if (entry->ifindex == ifindex)
            return entry;
        entry = entry->next;
    }
    return NULL;
}

link_entry_t *link_insert(link_table_t *table, int ifindex, const char *ifname)
{
    // --- check if already present (shouldn't be) ---
    link_entry_t *existing = link_lookup(table, ifindex);
    if (existing)
        return existing;

    // calloc new entry
    link_entry_t *entry = calloc(1, sizeof(*entry));
    if (!entry) return NULL;

    // fill fields:
    entry->ifindex = ifindex;
    strncpy(entry->ifname, ifname, IFNAMSIZ-1);
    entry->ifname[IFNAMSIZ-1] = '\0';  //
    entry->last_state = LINK_STATE_UNKNOWN;
    entry->last_event = time(NULL);
    entry->last_alert = 0;
    entry->flap_count = 0;


    // insert at HEAD of bucket chain
    uint32_t index = hash_ifindex(ifindex);
    entry->next = table->buckets[index];
    table->buckets[index] = entry;
    table->total_entries++;

    return entry;
}

int check_link_state(link_table_t *table, int ifindex,
                     const char *ifname, unsigned int ifi_flags)
{
    pthread_mutex_lock(&table->lock);

    // --- lookup or insert ---
    link_entry_t *entry = link_lookup(table, ifindex);
    if (!entry)
        entry = link_insert(table, ifindex, ifname);
    if (!entry)
    {
        pthread_mutex_unlock(&table->lock);
        return 0;
    }

    // --- compute new state from ifi_flags ---
    link_state_t new_state;
    if (ifi_flags & IFF_UP)
    {
        if (ifi_flags & IFF_RUNNING)
            new_state = LINK_STATE_UP;
        else
            new_state = LINK_STATE_DOWN;
    }
    else
        new_state = LINK_STATE_DISABLED;
        
    // --- compare to last known state ---
    if (new_state == entry->last_state)
    {
        // same state — just update last_event
        entry->last_event = time(NULL);
        pthread_mutex_unlock(&table->lock);
        return 0;
    }
    else
    {
        // state changed — update entry, log event
        link_state_t old_state = entry->last_state;
        entry->last_state = new_state;
        entry->last_event = time(NULL);
        if (new_state == LINK_STATE_DOWN)
            entry->flap_count++;

        pthread_mutex_unlock(&table->lock);
        log_link_event("ALERT", entry, old_state, new_state);
        return 1;
    }
}

void link_table_cleanup()
{
    pthread_mutex_lock(&g_link_table.lock);
    for (int i = 0; i < LINK_TABLE_SIZE; i++)
    {
        link_entry_t *entry = g_link_table.buckets[i];
        while (entry)
        {
            link_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
        g_link_table.buckets[i] = NULL;
    }

    g_link_table.total_entries = 0;
    pthread_mutex_unlock(&g_link_table.lock);
    pthread_mutex_destroy(&g_link_table.lock);
}

void start_link_monitor()
{
    link_table_init(&g_link_table);

    // --- create netlink socket ---
    int sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sockfd < 0)
    {
        perror("socket");
        exit(1);
    }

    // --- bind to RTMGRP_LINK multicast group ---
    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = RTMGRP_LINK;

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        close(sockfd);
        exit(1);
    }


    printf("[LAYER_1] Link state monitor active\n");
    printf("[LAYER_1] D3FEND: D3-NTA | ATT&CK: T1200\n");

    // --- receive buffer ---
    char buffer[LINK_BUFFER_SIZE];

    while (1)
    {
        // --- recvmsg() ---
        struct iovec iov = { buffer, sizeof(buffer) };
        struct sockaddr_nl src_addr;
        struct msghdr msg = { 0 };
        msg.msg_name = &src_addr;
        msg.msg_namelen = sizeof(src_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        ssize_t len = recvmsg(sockfd, &msg, 0);
        if (len < 0)
        {
            perror("recvmsg");
            continue;  // on error, skip this iteration but keep running
        }

        // --- walk netlink messages ---
        struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
        for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len))
        {
            if (nlh->nlmsg_type == NLMSG_DONE)
                break;
            if (nlh->nlmsg_type == NLMSG_ERROR)
            {
                fprintf(stderr, "Netlink error received\n");
                break;
            }
            if (nlh->nlmsg_type != RTM_NEWLINK)
                continue;
            
            // --- extract ifinfomsg ---
            struct ifinfomsg *ifi = NLMSG_DATA(nlh);

            // --- get interface name ---
            char ifname[IFNAMSIZ];
            if (if_indextoname(ifi->ifi_index, ifname) == NULL)
            {  
                fprintf(stderr, "Failed to get interface name for index %d\n", ifi->ifi_index);
                continue;
            }

            // --- call check_link_state ---
            check_link_state(&g_link_table, ifi->ifi_index,
                             ifname, ifi->ifi_flags);
        }
    }
}

void log_link_event(const char *action, link_entry_t *entry,
                    link_state_t old_state, link_state_t new_state)
{
    // --- timestamp ---
    time_t now = time(NULL);
    struct tm tm_buf;
    char timestamp[32];
    if (localtime_r(&now, &tm_buf) != NULL)
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_buf);
    else
        strncpy(timestamp, "unknown-time", sizeof(timestamp));

    // --- print log line ---'
    printf("[%s] [LAYER_1] [LINK] [%s] iface=%s old=%s new=%s flaps=%d d3fend=D3-NTA attck=T1200\n",
           timestamp, action, entry->ifname, state_name(old_state),
           state_name(new_state), entry->flap_count);
}
