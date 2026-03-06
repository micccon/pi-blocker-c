#include "enforce.h"
#include "net_hdrs.h"
#include <sys/socket.h>
#include <unistd.h>

// --- global state ---
static ip_entry_t *g_ip_buckets[ENFORCE_IP_BUCKETS];
static port_entry_t *g_port_buckets[ENFORCE_PORT_BUCKETS];
static proto_entry_t *g_proto_buckets[ENFORCE_PROTO_BUCKETS];
static pthread_mutex_t g_enforce_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t g_enforce_once = PTHREAD_ONCE_INIT;
static int g_chain_ready = 0;

// --- rst pseudo-header ---
// used for TCP checksum calculation (RFC 793)
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_len;
} __attribute__((packed)) tcp_pseudo_hdr_t;

// --- command helper ---
static int run_cmd(const char *cmd)
{
    // --- execute firewall command ---
    int rc = system(cmd);
    return (rc == 0) ? 0 : -1;
}

// --- checksum helper ---
static uint16_t checksum16(const void *data, size_t len)
{
    uint32_t sum = 0;
    const uint16_t *ptr = (const uint16_t *)data;

    while (len > 1)
    {
        sum += *ptr++;
        len -= 2;
    }

    if (len == 1)
        sum += *(const uint8_t *)ptr;

    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);

    return (uint16_t)(~sum);
}

// caller must hold g_enforce_lock
static int ensure_chain_ready_locked(void)
{
    // --- command buffer ---
    char cmd[ENFORCE_CMD_LEN];

    // --- fast path: chain already prepared ---
    if (g_chain_ready)
        return 0;

    // --- create dedicated chain if missing ---
    snprintf(cmd, sizeof(cmd),
             "iptables -L %s -n >/dev/null 2>&1 || iptables -N %s",
             ENFORCE_CHAIN_NAME, ENFORCE_CHAIN_NAME);
    if (run_cmd(cmd) != 0)
        return -1;

    // --- ensure INPUT jumps into dedicated chain ---
    snprintf(cmd, sizeof(cmd),
             "iptables -C INPUT -j %s >/dev/null 2>&1 || iptables -A INPUT -j %s",
             ENFORCE_CHAIN_NAME, ENFORCE_CHAIN_NAME);
    if (run_cmd(cmd) != 0)
        return -1;

    // --- ensure FORWARD jumps into dedicated chain ---
    snprintf(cmd, sizeof(cmd),
             "iptables -C FORWARD -j %s >/dev/null 2>&1 || iptables -A FORWARD -j %s",
             ENFORCE_CHAIN_NAME, ENFORCE_CHAIN_NAME);
    if (run_cmd(cmd) != 0)
        return -1;

    // --- mark ready for future calls ---
    g_chain_ready = 1;
    return 0;
}

static void enforce_once_init(void)
{
    // --- zero all hash bucket heads ---
    memset(g_ip_buckets, 0, sizeof(g_ip_buckets));
    memset(g_port_buckets, 0, sizeof(g_port_buckets));
    memset(g_proto_buckets, 0, sizeof(g_proto_buckets));
}

// --- hash helpers ---
static inline uint32_t ip_hash(uint32_t ip_nbo)
{
    return ntohl(ip_nbo) % ENFORCE_IP_BUCKETS;
}

static inline uint32_t port_hash(uint16_t port_hbo, uint8_t proto_num)
{
    uint32_t mixed = ((uint32_t)port_hbo * 2654435761u) ^ ((uint32_t)proto_num * 2246822519u);
    return mixed % ENFORCE_PORT_BUCKETS;
}

static inline uint32_t proto_hash(uint8_t proto_num)
{
    return proto_num % ENFORCE_PROTO_BUCKETS;
}

// --- locked lookup helpers ---
// caller must hold g_enforce_lock
static int ip_exists_locked(uint32_t ip_nbo)
{
    // --- choose bucket ---
    uint32_t idx = ip_hash(ip_nbo);

    // --- walk bucket chain ---
    ip_entry_t *entry = g_ip_buckets[idx];
    while (entry != NULL)
    {
        if (entry->ip_nbo == ip_nbo)
            return 1;
        entry = entry->next;
    }
    return 0;
}

static int port_exists_locked(uint16_t port_hbo, uint8_t proto_num)
{
    // --- choose bucket ---
    uint32_t idx = port_hash(port_hbo, proto_num);

    // --- walk bucket chain ---
    port_entry_t *entry = g_port_buckets[idx];
    while (entry != NULL)
    {
        if (entry->port_hbo == port_hbo && entry->proto_num == proto_num)
            return 1;
        entry = entry->next;
    }
    return 0;
}

static int proto_exists_locked(uint8_t proto_num)
{
    // --- choose bucket ---
    uint32_t idx = proto_hash(proto_num);

    // --- walk bucket chain ---
    proto_entry_t *entry = g_proto_buckets[idx];
    while (entry != NULL)
    {
        if (entry->proto_num == proto_num)
            return 1;
        entry = entry->next;
    }
    return 0;
}

// --- locked insert helpers ---
// caller must hold g_enforce_lock
static int ip_insert_locked(uint32_t ip_nbo)
{
    // --- allocate entry ---
    uint32_t idx = ip_hash(ip_nbo);
    ip_entry_t *entry = calloc(1, sizeof(*entry));
    if (!entry)
        return -1;

    // --- insert at bucket head ---
    entry->ip_nbo = ip_nbo;
    entry->next = g_ip_buckets[idx];
    g_ip_buckets[idx] = entry;
    return 0;
}

static int port_insert_locked(uint16_t port_hbo, uint8_t proto_num)
{
    // --- allocate entry ---
    uint32_t idx = port_hash(port_hbo, proto_num);
    port_entry_t *entry = calloc(1, sizeof(*entry));
    if (!entry)
        return -1;

    // --- insert at bucket head ---
    entry->port_hbo = port_hbo;
    entry->proto_num = proto_num;
    entry->next = g_port_buckets[idx];
    g_port_buckets[idx] = entry;
    return 0;
}

static int proto_insert_locked(uint8_t proto_num)
{
    // --- allocate entry ---
    uint32_t idx = proto_hash(proto_num);
    proto_entry_t *entry = calloc(1, sizeof(*entry));
    if (!entry)
        return -1;

    // --- insert at bucket head ---
    entry->proto_num = proto_num;
    entry->next = g_proto_buckets[idx];
    g_proto_buckets[idx] = entry;
    return 0;
}

// --- protocol helper ---
static const char *proto_to_name(uint8_t proto_num)
{
    switch (proto_num)
    {
        case IPPROTO_TCP:  return "tcp";
        case IPPROTO_UDP:  return "udp";
        case IPPROTO_ICMP: return "icmp";
        default:           return NULL;
    }
}

// --- iptables apply helpers ---
// caller must hold g_enforce_lock
static int apply_ip_block_locked(uint32_t src_ip_nbo)
{
    // --- convert source IP to dotted string ---
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr = { .s_addr = src_ip_nbo };
    char cmd[ENFORCE_CMD_LEN];

    if (!inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str)))
        return -1;

    // --- add DROP rule if it does not already exist ---
    snprintf(cmd, sizeof(cmd),
             "iptables -C %s -s %s -j DROP >/dev/null 2>&1 || iptables -A %s -s %s -j DROP",
             ENFORCE_CHAIN_NAME, ip_str, ENFORCE_CHAIN_NAME, ip_str);
    return run_cmd(cmd);
}

static int apply_port_block_locked(uint16_t port_hbo, uint8_t proto_num)
{
    // --- normalize protocol string ---
    const char *proto = proto_to_name(proto_num);
    char cmd[ENFORCE_CMD_LEN];

    if (!proto)
        return -1;
    // dport rules apply to tcp/udp only
    if (proto_num != IPPROTO_TCP && proto_num != IPPROTO_UDP)
        return -1;

    // --- add DROP rule if it does not already exist ---
    snprintf(cmd, sizeof(cmd),
             "iptables -C %s -p %s --dport %u -j DROP >/dev/null 2>&1 || iptables -A %s -p %s --dport %u -j DROP",
             ENFORCE_CHAIN_NAME, proto, (unsigned int)port_hbo,
             ENFORCE_CHAIN_NAME, proto, (unsigned int)port_hbo);
    return run_cmd(cmd);
}

static int apply_proto_block_locked(uint8_t proto_num)
{
    // --- normalize protocol string ---
    const char *proto = proto_to_name(proto_num);
    char cmd[ENFORCE_CMD_LEN];

    if (!proto)
        return -1;

    // --- add protocol-wide DROP rule if missing ---
    snprintf(cmd, sizeof(cmd),
             "iptables -C %s -p %s -j DROP >/dev/null 2>&1 || iptables -A %s -p %s -j DROP",
             ENFORCE_CHAIN_NAME, proto, ENFORCE_CHAIN_NAME, proto);
    return run_cmd(cmd);
}

// --- packet action helper ---
void rst_inject(int raw_fd, uint32_t src_ip, uint16_t src_port,
                uint32_t dst_ip, uint16_t dst_port, uint32_t ack_num)
{
    // --- validate socket fd ---
    if (raw_fd < 0)
        return;

    // --- enable IP_HDRINCL on this socket ---
    int one = 1;
    if (setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        perror("Failed to set IP_HDRINCL");
        return;
    }

    // --- build packet buffer ---
    const size_t packet_len = sizeof(struct ip_hdr) + sizeof(struct tcp_hdr);
    unsigned char packet[sizeof(struct ip_hdr) + sizeof(struct tcp_hdr)];
    memset(packet, 0, sizeof(packet));

    // --- fill IPv4 header ---
    struct ip_hdr *ip = (struct ip_hdr *)packet;
    ip->version_ihl = 0x45; // IPv4 + IHL 5 (20 bytes)
    ip->tos = 0;
    ip->total_length = htons((uint16_t)packet_len);
    ip->id = 0;
    ip->flags_fragment = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->src_addr = dst_ip; // spoof as server/source side
    ip->dst_addr = src_ip; // send toward client/source side
    ip->checksum = 0;

    // --- fill TCP header ---
    struct tcp_hdr *tcp = (struct tcp_hdr *)(packet + sizeof(struct ip_hdr));
    tcp->src_port = htons(dst_port);
    tcp->dst_port = htons(src_port);
    tcp->seq_num = ack_num;
    tcp->ack_num = 0;
    tcp->data_offset = 0x50; // 5 * 4 = 20-byte header
    tcp->flags = 0x04;       // RST
    tcp->window = 0;
    tcp->checksum = 0;
    tcp->urgent_ptr = 0;

    // --- build pseudo-header buffer for TCP checksum ---
    tcp_pseudo_hdr_t pseudo;
    pseudo.src_ip = ip->src_addr;
    pseudo.dst_ip = ip->dst_addr;
    pseudo.zero = 0;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.tcp_len = htons(sizeof(struct tcp_hdr));

    unsigned char csum_buf[sizeof(tcp_pseudo_hdr_t) + sizeof(struct tcp_hdr)];
    memcpy(csum_buf, &pseudo, sizeof(pseudo));
    memcpy(csum_buf + sizeof(pseudo), tcp, sizeof(struct tcp_hdr));

    // --- set checksums ---
    tcp->checksum = checksum16(csum_buf, sizeof(csum_buf));
    ip->checksum = checksum16(ip, sizeof(struct ip_hdr));

    // --- build destination socket address ---
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = src_ip;
    dst.sin_port = htons(src_port);

    // --- send crafted packet ---
    if (sendto(raw_fd, packet, sizeof(packet), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
        perror("Failed to send RST packet");
}

// --- public API: block rules ---
int block_ip(uint32_t src_ip_nbo)
{
    // --- default to failure ---
    int rc = -1;

    // --- one-time init + lock ---
    pthread_once(&g_enforce_once, enforce_once_init);
    pthread_mutex_lock(&g_enforce_lock);

    // --- ensure chain exists and is linked ---
    if (ensure_chain_ready_locked() != 0)
        goto out;

    // --- dedupe: already tracked ---
    if (ip_exists_locked(src_ip_nbo))
    {
        rc = 0;
        goto out;
    }

    // --- apply firewall rule ---
    if (apply_ip_block_locked(src_ip_nbo) != 0)
        goto out;

    // --- record in local hash table ---
    rc = ip_insert_locked(src_ip_nbo);

out:
    // --- unlock + return ---
    pthread_mutex_unlock(&g_enforce_lock);
    return rc;
}

int block_port(uint16_t port_hbo, uint8_t proto_num)
{
    // --- default to failure ---
    int rc = -1;

    // --- one-time init + lock ---
    pthread_once(&g_enforce_once, enforce_once_init);
    pthread_mutex_lock(&g_enforce_lock);

    // --- ensure chain exists and is linked ---
    if (ensure_chain_ready_locked() != 0)
        goto out;

    // --- dedupe: already tracked ---
    if (port_exists_locked(port_hbo, proto_num))
    {
        rc = 0;
        goto out;
    }

    // --- apply firewall rule ---
    if (apply_port_block_locked(port_hbo, proto_num) != 0)
        goto out;

    // --- record in local hash table ---
    rc = port_insert_locked(port_hbo, proto_num);

out:
    // --- unlock + return ---
    pthread_mutex_unlock(&g_enforce_lock);
    return rc;
}

int block_proto(uint8_t proto_num)
{
    // --- default to failure ---
    int rc = -1;

    // --- one-time init + lock ---
    pthread_once(&g_enforce_once, enforce_once_init);
    pthread_mutex_lock(&g_enforce_lock);

    // --- ensure chain exists and is linked ---
    if (ensure_chain_ready_locked() != 0)
        goto out;

    // --- dedupe: already tracked ---
    if (proto_exists_locked(proto_num))
    {
        rc = 0;
        goto out;
    }

    // --- apply firewall rule ---
    if (apply_proto_block_locked(proto_num) != 0)
        goto out;

    // --- record in local hash table ---
    rc = proto_insert_locked(proto_num);

out:
    // --- unlock + return ---
    pthread_mutex_unlock(&g_enforce_lock);
    return rc;
}

// --- public API: query rules ---
bool is_ip_blocked(uint32_t src_ip_nbo)
{
    // --- read under lock for thread safety ---
    int exists;
    pthread_once(&g_enforce_once, enforce_once_init);
    pthread_mutex_lock(&g_enforce_lock);
    exists = ip_exists_locked(src_ip_nbo);
    pthread_mutex_unlock(&g_enforce_lock);
    return exists != 0;
}

bool is_port_blocked(uint16_t port_hbo, uint8_t proto_num)
{
    // --- read under lock for thread safety ---
    int exists;
    pthread_once(&g_enforce_once, enforce_once_init);
    pthread_mutex_lock(&g_enforce_lock);
    exists = port_exists_locked(port_hbo, proto_num);
    pthread_mutex_unlock(&g_enforce_lock);
    return exists != 0;
}

bool is_proto_blocked(uint8_t proto_num)
{
    // --- read under lock for thread safety ---
    int exists;
    pthread_once(&g_enforce_once, enforce_once_init);
    pthread_mutex_lock(&g_enforce_lock);
    exists = proto_exists_locked(proto_num);
    pthread_mutex_unlock(&g_enforce_lock);
    return exists != 0;
}

// --- cleanup helpers ---
static void free_ip_table_locked(void)
{
    // --- free every entry in every IP bucket ---
    for (int i = 0; i < ENFORCE_IP_BUCKETS; i++)
    {
        ip_entry_t *entry = g_ip_buckets[i];
        while (entry != NULL)
        {
            ip_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
        g_ip_buckets[i] = NULL;
    }
}

static void free_port_table_locked(void)
{
    // --- free every entry in every port bucket ---
    for (int i = 0; i < ENFORCE_PORT_BUCKETS; i++)
    {
        port_entry_t *entry = g_port_buckets[i];
        while (entry != NULL)
        {
            port_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
        g_port_buckets[i] = NULL;
    }
}

static void free_proto_table_locked(void)
{
    // --- free every entry in every protocol bucket ---
    for (int i = 0; i < ENFORCE_PROTO_BUCKETS; i++)
    {
        proto_entry_t *entry = g_proto_buckets[i];
        while (entry != NULL)
        {
            proto_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
        g_proto_buckets[i] = NULL;
    }
}

// --- public API: cleanup ---
void enforce_cleanup(void)
{
    // --- command buffer ---
    char cmd[ENFORCE_CMD_LEN];

    // --- one-time init + lock ---
    pthread_once(&g_enforce_once, enforce_once_init);
    pthread_mutex_lock(&g_enforce_lock);

    // --- unlink chain from INPUT if present ---
    snprintf(cmd, sizeof(cmd),
             "iptables -D INPUT -j %s >/dev/null 2>&1 || true",
             ENFORCE_CHAIN_NAME);
    run_cmd(cmd);

    // --- unlink chain from FORWARD if present ---
    snprintf(cmd, sizeof(cmd),
             "iptables -D FORWARD -j %s >/dev/null 2>&1 || true",
             ENFORCE_CHAIN_NAME);
    run_cmd(cmd);

    // --- flush all rules in our chain ---
    snprintf(cmd, sizeof(cmd),
             "iptables -F %s >/dev/null 2>&1 || true",
             ENFORCE_CHAIN_NAME);
    run_cmd(cmd);

    // --- delete empty chain ---
    snprintf(cmd, sizeof(cmd),
             "iptables -X %s >/dev/null 2>&1 || true",
             ENFORCE_CHAIN_NAME);
    run_cmd(cmd);

    // --- reset local state ---
    g_chain_ready = 0;
    free_ip_table_locked();
    free_port_table_locked();
    free_proto_table_locked();

    // --- release lock ---
    pthread_mutex_unlock(&g_enforce_lock);
}
