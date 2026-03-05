#include "arp_monitor.h"

// --- global ARP table ---
static arp_table_t g_arp_table;


// --- internal hash function ---
// hash an IP address to a bucket index
static uint32_t hash_ip(uint32_t ip)
{
    // same pattern as every other layer
    return ip % ARP_TABLE_SIZE;
}

// --- prune helper ---
// caller must hold table->lock
// removes stale IP->MAC mappings to free capacity
static void arp_prune_stale_locked(arp_table_t *table, time_t now)
{
    for (int i = 0; i < ARP_TABLE_SIZE; i++)
    {
        arp_entry_t **cursor = &table->buckets[i];
        while (*cursor != NULL)
        {
            arp_entry_t *entry = *cursor;
            if (now - entry->last_seen > ARP_STALE_SECONDS)
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

void arp_table_init(arp_table_t *table)
{
    memset(table->buckets, 0, sizeof(table->buckets));
    table->total_entries = 0;
    // initialize mutex and check for errors
    int result = pthread_mutex_init(&table->lock, NULL);
    if (result != 0)
    {
        fprintf(stderr, "Failed to initialize ARP table mutex: %s\n", strerror(result));
        exit(1);
    }
}

arp_entry_t *arp_lookup(arp_table_t *table, uint32_t ip)
{
    int index = hash_ip(ip);
    arp_entry_t *entry = table->buckets[index];

    // --- walk bucket chain ---
    while (entry != NULL)
    {
        if (entry->ip == ip)
            return entry;
        entry = entry->next;
    }
    return NULL;
}

arp_entry_t *arp_insert(arp_table_t *table, uint32_t ip, uint8_t mac[6])
{
    // --- check if table is full ---
    // try stale-entry pruning before failing insert
    if (table->total_entries >= ARP_ENTRY_MAX)
    {
        arp_prune_stale_locked(table, time(NULL));
        if (table->total_entries >= ARP_ENTRY_MAX)
            return NULL;
    }

    arp_entry_t *entry = calloc(1, sizeof(*entry));
    if (!entry)
        return NULL;
    
    // Set entry data
    entry->ip = ip;
    memcpy(entry->mac, mac, 6);
    entry->last_seen = time(NULL);
    entry->next = NULL;

    // Hash theip and add it to table, set table head
    int index = hash_ip(ip);
    entry->next = table->buckets[index];
    table->buckets[index] = entry;
    table->total_entries++;

    return entry;
}

void arp_update(arp_entry_t *entry, uint8_t mac[6])
{
    memcpy(entry->mac, mac, sizeof(entry->mac));
    entry->last_seen = time(NULL);
}

int check_arp_spoof(arp_table_t *table, uint32_t sender_ip,
                    uint8_t sender_mac[6], uint8_t old_mac_out[6])
{
    pthread_mutex_lock(&table->lock);
    arp_entry_t *entry = arp_lookup(table, sender_ip);

    if (entry != NULL)
    {
        // --- check if MAC has changed ---
        if (memcmp(entry->mac, sender_mac, 6) != 0)
        {
            // save old MAC for logging before updating
            memcpy(old_mac_out, entry->mac, 6);

            // update to new MAC — attacker already poisoned the network
            arp_update(entry, sender_mac);

            pthread_mutex_unlock(&table->lock);
            return 1;  // spoof detected — caller logs old_mac vs sender_mac
        }

        // same MAC — just update last_seen
        arp_update(entry, sender_mac);
        pthread_mutex_unlock(&table->lock);
        return 0;
    }

    // new IP — insert mapping ---
    // if insert fails (table full or alloc failure), return error signal
    if (arp_insert(table, sender_ip, sender_mac) == NULL)
    {
        pthread_mutex_unlock(&table->lock);
        return -1;
    }
    pthread_mutex_unlock(&table->lock);
    return 0;
}

void arp_table_cleanup()
{
    // --- free all entries in all buckets ---
    pthread_mutex_lock(&g_arp_table.lock);
    for (int i = 0; i < ARP_TABLE_SIZE; i++)
    {
        arp_entry_t *entry = g_arp_table.buckets[i];
        while (entry)
        {
            arp_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
        g_arp_table.buckets[i] = NULL;
    }

    g_arp_table.total_entries = 0;
    pthread_mutex_unlock(&g_arp_table.lock);
    pthread_mutex_destroy(&g_arp_table.lock);
}

void start_arp_monitor()
{
    // --- initialize ARP table ---
    arp_table_init(&g_arp_table);

    // --- create AF_PACKET raw socket ---
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0)
    {
        perror("Failed to create raw socket");
        exit(1);
    }

    printf("[LAYER_2] ARP monitor active\n");
    printf("[LAYER_2] D3FEND: D3-AAF | ATT&CK: T1557.002\n");

    while (1)
    {
        // --- allocate task ---
        arp_task_t *task = calloc(1, sizeof(arp_task_t));
        if (!task)
        {
            fprintf(stderr, "Failed to allocate memory for ARP task\n");
            continue;  // skip this packet but keep running
        }

        // --- recvfrom into task->buffer ---
        ssize_t bytes = recvfrom(sockfd, task->buffer, sizeof(task->buffer), 0,
                                (struct sockaddr *)&task->src_addr,
                                &(socklen_t){sizeof(task->src_addr)});
        if (bytes < 0)
        {
            perror("Failed to receive packet");
            free(task);
            continue;
        }

        // --- validate packet length ---
        if (bytes < (ssize_t)(sizeof(struct eth_hdr) + sizeof(struct arp_pkt)))
        {
            fprintf(stderr, "Received packet too small for ARP\n");
            free(task);
            continue;
        }
        task->packet_len = bytes;

        // --- parse Ethernet header ---
        struct eth_hdr *eth = (struct eth_hdr *)task->buffer;
        if (ntohs(eth->ethertype) != ETHERTYPE_ARP)
        {
            // not an ARP packet → ignore
            free(task);
            continue;
        }

        // --- parse ARP packet ---
        struct arp_pkt *arp = (struct arp_pkt *)(task->buffer + sizeof(struct eth_hdr));

        // --- filter ARP replies only ---
        if (ntohs(arp->oper) != 2)
        {
            // not an ARP reply → ignore
            free(task);
            continue;
        }

        // --- filter IPv4 over Ethernet only ---
        if (ntohs(arp->htype) != 1 || ntohs(arp->ptype) != ETHERTYPE_IPV4 ||
            arp->hlen != 6 || arp->plen != 4)
        {
            // not Ethernet+IPv4 ARP → ignore
            free(task);
            continue;
        }

        // --- spawn thread ---
        pthread_t thread_id;
        int result = pthread_create(&thread_id, NULL, handle_arp_packet, task);
        if (result != 0)
        {
            fprintf(stderr, "Failed to create thread for ARP packet: %s\n", strerror(result));
            free(task);
            continue;
        }
        pthread_detach(thread_id);
    }
}

void *handle_arp_packet(void *arg)
{
    arp_task_t *task = (arp_task_t *)arg;

    // --- parse Ethernet and ARP headers ---
    struct arp_pkt *arp = (struct arp_pkt *)(task->buffer + sizeof(struct eth_hdr));

    // --- extract sender IP and MAC ---
    uint32_t sender_ip = arp->spa;
    uint8_t sender_mac[6];
    memcpy(sender_mac, arp->sha, 6);

    // --- check for spoof ---
    uint8_t old_mac[6];
    int spoofed = check_arp_spoof(&g_arp_table, sender_ip, sender_mac, old_mac);

    // --- if spoofed ---
    if (spoofed > 0)
    {
        log_arp_decision("ALERT", sender_ip, sender_mac, old_mac);
    }
    else if (spoofed < 0)
    {
        log_arp_decision("ERROR", sender_ip, sender_mac, NULL);
    }
    else
        log_arp_decision("OK", sender_ip, sender_mac, NULL);
    
    // --- cleanup ---
    free(task);
    return NULL;
}

void log_arp_decision(const char *action, uint32_t ip,
                      uint8_t mac[6], uint8_t old_mac[6])
{
    // --- timestamp ---
    time_t now = time(NULL);
    struct tm tm_buf;
    char time_str[20];
    if (localtime_r(&now, &tm_buf) != NULL)
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);
    else
        strncpy(time_str, "unknown-time", sizeof(time_str));

    // --- format IP as string ---
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr = { .s_addr = ip };
    if (inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str)) == NULL)
    {
        strncpy(ip_str, "unknown-ip", sizeof(ip_str));
        ip_str[sizeof(ip_str) - 1] = '\0';
    }

    // --- format MAC as string ---
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // --- if ALERT, also format old MAC for logging ---
    char old_mac_str[18] = "N/A";
    if (old_mac)
    {
        snprintf(old_mac_str, sizeof(old_mac_str),
                "%02x:%02x:%02x:%02x:%02x:%02x",
                 old_mac[0], old_mac[1], old_mac[2], old_mac[3], old_mac[4], old_mac[5]);
    }

    // --- print structured ARP decision log ---
    printf("[%s] [LAYER_2] [ARP] [%s] ip=%s mac=%s old_mac=%s d3fend=D3-AAF attck=T1557.002\n",
           time_str, action, ip_str, mac_str, old_mac_str);
}
