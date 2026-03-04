#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "tls_inspector.h"
#include "../layer_7/dns/dns.h"  // for is_blocked()
#include "../common/net_hdrs.h"  // for struct ip_hdr and struct tcp_hdr
#include <ctype.h>

void start_tls_inspector()
{
    // --- create raw socket ---
    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_fd < 0)
    {
        perror("Failed to create raw socket (are you root?)");
        exit(1);
    }

    printf("TLS Inspector listening on all interfaces (port 443 traffic)\n");
    printf("D3FEND: D3-TLSIC | ATT&CK: T1573\n");

    // --- capture loop ---
    while (1)
    {
        // --- minimum size check ---
        tls_task_t *task = calloc(1, sizeof(tls_task_t));
        if (!task) continue;

        // --- receive raw packet ---
        socklen_t addr_len = sizeof(task->src_addr);
        task->packet_len = recvfrom(raw_fd, task->buffer, TLS_BUFFER_SIZE, 0,
                                    (struct sockaddr *)&task->src_addr, &addr_len);
        if (task->packet_len < 0)
        {
            free(task);
            continue;
        }

        // --- validate and parse IP header ---
        struct ip_hdr *ip_header = (struct ip_hdr *)task->buffer;
        size_t ip_hdr_len = (ip_header->version_ihl & 0x0F) * 4;
        if (ip_hdr_len < 20 || (int)ip_hdr_len > task->packet_len)
        {
            free(task);
            continue;
        }

        // --- filter port 443 only ---
        struct tcp_hdr *tcp_header = (struct tcp_hdr *)(task->buffer + ip_hdr_len);
        if (ntohs(tcp_header->dst_port) != HTTPS_PORT)
        {
            free(task);
            continue;
        }

        // --- validate TCP header ---
        size_t tcp_hdr_len = ((tcp_header->data_offset & 0xF0) >> 4) * 4;
        if (tcp_hdr_len < 20 || (int)(ip_hdr_len + tcp_hdr_len) > task->packet_len)
        {
            free(task);
            continue;
        }

        // --- fast filter: is this a TLS ClientHello? ---
        unsigned char *tls_start = task->buffer + ip_hdr_len + tcp_hdr_len;
        int tls_len = task->packet_len - (int)ip_hdr_len - (int)tcp_hdr_len;

        if (!is_tls_client_hello(tls_start, tls_len))
        {
            free(task);
            continue;
        }

        // --- store raw_fd for RST injection (implement after Layer 4) ---
        task->raw_fd = raw_fd;

        // --- spawn thread ---
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_tls_packet, task) != 0)
        {
            free(task);
            continue;
        }
        pthread_detach(thread_id);
    }
}

int is_tls_client_hello(unsigned char *buffer, int len)
{
    // --- minimum size check ---
    if (!buffer || len < TLS_RECORD_HEADER_SIZE + TLS_HANDSHAKE_HEADER_SIZE)
        return 0;

    // --- check content type ---
    struct tls_record_hdr *record_hdr = (struct tls_record_hdr *)buffer;
    if (record_hdr->content_type != TLS_CONTENT_TYPE_HANDSHAKE)
        return 0;

    // --- check handshake type ---
    struct tls_handshake_hdr *handshake_hdr =
        (struct tls_handshake_hdr *)(buffer + TLS_RECORD_HEADER_SIZE);
    if (handshake_hdr->handshake_type != TLS_HANDSHAKE_CLIENT_HELLO)
        return 0;

    return 1;
}

int extract_sni(unsigned char *buffer, int len,
                        char *hostname, int hostname_len)
{
    // --- initial checks ---
    if (!buffer || !hostname || hostname_len <= 1)
        return -1;

    int pos = TLS_RECORD_HEADER_SIZE + TLS_HANDSHAKE_HEADER_SIZE;

    // skip legacy_version (2) + random (32)
    CHECK_BOUNDS(pos, 2 + 32, len);
    pos += 2 + 32;

    // --- skip session_id ---
    CHECK_BOUNDS(pos, 1, len);
    uint8_t session_id_len = buffer[pos];
    CHECK_BOUNDS(pos, 1 + session_id_len, len);
    pos += 1 + session_id_len;

    // --- skip cipher_suites ---
    CHECK_BOUNDS(pos, 2, len);
    uint16_t cipher_suites_len = ntohs(*(uint16_t *)(buffer + pos));
    CHECK_BOUNDS(pos, 2 + cipher_suites_len, len);
    pos += 2 + cipher_suites_len;

    // --- skip compression methods ---
    CHECK_BOUNDS(pos, 1, len);
    uint8_t compression_len = buffer[pos];
    CHECK_BOUNDS(pos, 1 + compression_len, len);
    pos += 1 + compression_len;

    // --- read extensions length ---
    CHECK_BOUNDS(pos, 2, len);
    uint16_t extensions_len = ntohs(*(uint16_t *)(buffer + pos));
    pos += 2;
    CHECK_BOUNDS(pos, extensions_len, len);
    int extensions_end = pos + extensions_len;

    // walk extensions
    while (pos + 4 <= extensions_end && pos + 4 <= len)
    {
        uint16_t ext_type = ntohs(*(uint16_t *)(buffer + pos));
        pos += 2;

        // --- read extension length and validate bounds ---
        uint16_t ext_len = ntohs(*(uint16_t *)(buffer + pos));
        pos += 2;

        if (pos + ext_len > extensions_end || pos + ext_len > len)
            return -1;

        if (ext_type == TLS_EXT_SNI)
        {
            // RFC 6066 section 3 — SNI structure:
            //   server_name_list_length (2)
            //   name_type               (1) — 0x00 = host_name
            //   name_length             (2)
            //   name                    (variable)
            int sni_pos = pos;
            int sni_end = pos + ext_len;

            CHECK_BOUNDS(sni_pos, 2, sni_end);
            sni_pos += 2; // skip list length

            CHECK_BOUNDS(sni_pos, 1, sni_end);
            uint8_t name_type = buffer[sni_pos];
            sni_pos += 1;

            if (name_type != TLS_SNI_HOST_NAME)
                return -1;

            CHECK_BOUNDS(sni_pos, 2, sni_end);
            uint16_t name_len = ntohs(*(uint16_t *)(buffer + sni_pos));
            sni_pos += 2;

            CHECK_BOUNDS(sni_pos, name_len, sni_end);

            int copy_len = (name_len < hostname_len - 1) ? name_len : (hostname_len - 1);
            memcpy(hostname, buffer + sni_pos, copy_len);
            hostname[copy_len] = '\0';

            for (int i = 0; hostname[i]; i++)
                hostname[i] = tolower((unsigned char)hostname[i]);

            return 0;
        }

        pos += ext_len;
    }

    return -1;
}

int extract_alpn(unsigned char *buffer, int len, tls_task_t *task)
{
    // RFC 7301 section 3.1 — ALPN extension structure:
    //   protocol_name_list_length (2)
    //   protocol_name_length      (1)
    //   protocol_name             (variable)
    if (!buffer || len < 4) return -1;

    int pos = 0;

    CHECK_BOUNDS(pos, 2, len);
    pos += 2; // skip list length

    CHECK_BOUNDS(pos, 1, len);
    uint8_t name_len = buffer[pos];
    pos += 1;

    CHECK_BOUNDS(pos, name_len, len);
    if (name_len >= (int)sizeof(task->alpn))
        name_len = sizeof(task->alpn) - 1;

    memcpy(task->alpn, buffer + pos, name_len);
    task->alpn[name_len] = '\0';

    return 0;
}

int parse_client_hello(unsigned char *buffer, int len, tls_task_t *task)
{
    if (!is_tls_client_hello(buffer, len))
        return 0;

    task->client_hello_size = len;

    int pos = TLS_RECORD_HEADER_SIZE + TLS_HANDSHAKE_HEADER_SIZE;

    // extract legacy_version
    CHECK_BOUNDS_ZERO(pos, 2, len);
    task->tls_version = ntohs(*(uint16_t *)(buffer + pos));
    pos += 2;

    // skip random (32 bytes)
    CHECK_BOUNDS_ZERO(pos, 32, len);
    pos += 32;

    // skip session_id
    CHECK_BOUNDS_ZERO(pos, 1, len);
    uint8_t session_id_len = buffer[pos];
    CHECK_BOUNDS_ZERO(pos, 1 + session_id_len, len);
    pos += 1 + session_id_len;

    // skip cipher_suites
    CHECK_BOUNDS_ZERO(pos, 2, len);
    uint16_t cipher_suites_len = ntohs(*(uint16_t *)(buffer + pos));
    CHECK_BOUNDS_ZERO(pos, 2 + cipher_suites_len, len);
    pos += 2 + cipher_suites_len;

    // skip compression methods
    CHECK_BOUNDS_ZERO(pos, 1, len);
    uint8_t compression_len = buffer[pos];
    CHECK_BOUNDS_ZERO(pos, 1 + compression_len, len);
    pos += 1 + compression_len;

    // read extensions block — no extensions is still valid
    if (pos + 2 > len)
        goto done_extensions;

    uint16_t extensions_len = ntohs(*(uint16_t *)(buffer + pos));
    pos += 2;

    if (pos + extensions_len > len)
        goto done_extensions;

    int extensions_end = pos + extensions_len;

    // walk extensions, count them and extract ALPN
    task->extension_count = 0;
    while (pos + 4 <= extensions_end && pos + 4 <= len)
    {
        uint16_t ext_type = ntohs(*(uint16_t *)(buffer + pos));
        pos += 2;
        uint16_t ext_len = ntohs(*(uint16_t *)(buffer + pos));
        pos += 2;

        if (pos + ext_len > extensions_end || pos + ext_len > len)
            break;

        task->extension_count++;

        if (ext_type == TLS_EXT_ALPN)
            extract_alpn(buffer + pos, ext_len, task);

        pos += ext_len;
    }

done_extensions:
    // extract SNI — sets sni_present flag
    task->sni_present = 0;
    if (extract_sni(buffer, len, task->hostname, TLS_MAX_HOSTNAME_LEN) == 0)
        task->sni_present = 1;

    return 1;
}

tls_policy_verdict_t check_tls_policy(tls_task_t *task)
{
    // policy 1 — block missing SNI
    // legitimate browsers always send SNI
    // missing SNI = red flag for C2 or evasion tool — T1573
    if (!task->sni_present)
        return POLICY_BLOCK_NO_SNI;

    // policy 2 — block deprecated TLS versions
    // TLS 1.0 and 1.1 deprecated by RFC 8996
    // block anything below TLS 1.2 (0x0303)
    if (task->tls_version < TLS_MIN_VERSION)
        return POLICY_BLOCK_OLD_TLS;

    // policy 3 — alert on suspicious ALPN
    // legitimate HTTPS uses "h2" or "http/1.1"
    // anything else on port 443 may be C2 tunneling — T1071
    if (task->alpn[0] != '\0' &&
        strcmp(task->alpn, "h2")       != 0 &&
        strcmp(task->alpn, "http/1.1") != 0 &&
        strcmp(task->alpn, "http/1.0") != 0)
        return POLICY_ALERT_ALPN;

    // policy 4 — alert on anomalous extension count
    // real browsers send 10-20 extensions
    // very few or very many suggests a non-standard TLS client
    if (task->extension_count > TLS_MAX_EXTENSION_COUNT)
        return POLICY_ALERT_EXT_COUNT;

    // policy 5 — alert on oversized ClientHello
    if (task->client_hello_size > TLS_MAX_CLIENTHELLO_SIZE)
        return POLICY_ALERT_LARGE_HELLO;

    return POLICY_PASS;
}

// ============================================================
// enforce_block
// Layer 4 enforcement hook
// TODO: implement TCP RST injection after Layer 4 is complete
// ============================================================

void enforce_block(tls_task_t *task)
{
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &task->src_addr.sin_addr, src_ip, sizeof(src_ip));
    printf("[LAYER_6] [ENFORCE] would RST connection from %s host=%s\n",
           src_ip, task->hostname[0] ? task->hostname : "unknown");
}

void *handle_tls_packet(void *arg)
{
    tls_task_t *task = (tls_task_t *)arg;

    // --- locate TLS payload within raw packet ---
    struct ip_hdr *ip_header = (struct ip_hdr *)task->buffer;
    size_t ip_hdr_len = (ip_header->version_ihl & 0x0F) * 4;
    if (ip_hdr_len < 20 || (int)ip_hdr_len > task->packet_len)
    {
        free(task);
        return NULL;
    }

    struct tcp_hdr *tcp_header = (struct tcp_hdr *)(task->buffer + ip_hdr_len);
    size_t tcp_hdr_len = ((tcp_header->data_offset & 0xF0) >> 4) * 4;
    if (tcp_hdr_len < 20 || (int)(ip_hdr_len + tcp_hdr_len) > task->packet_len)
    {
        free(task);
        return NULL;
    }

    unsigned char *tls_start = task->buffer + ip_hdr_len + tcp_hdr_len;
    int tls_len = task->packet_len - (int)ip_hdr_len - (int)tcp_hdr_len;

    if (tls_len < TLS_RECORD_HEADER_SIZE + TLS_HANDSHAKE_HEADER_SIZE)
    {
        free(task);
        return NULL;
    }

    // --- parse ClientHello and fill task metadata ---
    if (!parse_client_hello(tls_start, tls_len, task))
    {
        free(task);
        return NULL;
    }

    // --- run policy engine ---
    task->verdict = check_tls_policy(task);

    // --- enforce block verdicts ---
    if (task->verdict == POLICY_BLOCK_NO_SNI ||
        task->verdict == POLICY_BLOCK_OLD_TLS)
    {
        enforce_block(task);
        log_policy_decision(task->verdict, task);
        free(task);
        return NULL;
    }

    // --- check blocklist if SNI was present ---
    if (task->sni_present && is_blocked(task->hostname))
    {
        task->verdict = POLICY_BLOCK_NO_SNI;
        enforce_block(task);
        log_policy_decision(task->verdict, task);
        free(task);
        return NULL;
    }

    // --- log alerts and allowed ---
    log_policy_decision(task->verdict, task);

    free(task);
    return NULL;
}

void log_policy_decision(tls_policy_verdict_t verdict, tls_task_t *task)
{
    const char *action;
    const char *attck;

    switch (verdict)
    {
        case POLICY_BLOCK_NO_SNI:
            action = "BLOCKED (no SNI)";
            attck  = "T1573";
            break;
        case POLICY_BLOCK_OLD_TLS:
            action = "BLOCKED (deprecated TLS)";
            attck  = "T1573";
            break;
        case POLICY_ALERT_ALPN:
            action = "ALERT (suspicious ALPN)";
            attck  = "T1071";
            break;
        case POLICY_ALERT_EXT_COUNT:
            action = "ALERT (anomalous extensions)";
            attck  = "T1573";
            break;
        case POLICY_ALERT_LARGE_HELLO:
            action = "ALERT (oversized ClientHello)";
            attck  = "T1573";
            break;
        default:
            action = "ALLOWED";
            attck  = "T1573";
            break;
    }

    time_t now = time(NULL);
    struct tm tm_buf;
    char timestamp[32];
    char src_ip[INET_ADDRSTRLEN] = "unknown";

    if (localtime_r(&now, &tm_buf) != NULL)
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_buf);

    if (task)
        inet_ntop(AF_INET, &task->src_addr.sin_addr, src_ip, sizeof(src_ip));

    printf("[%s] [LAYER_6] [TLS] [%s] host=%s src=%s "
           "tls_ver=0x%04X ext_count=%d alpn=%s "
           "d3fend=D3-TLSIC attck=%s\n",
           timestamp, action,
           (task && task->hostname[0]) ? task->hostname : "unknown",
           src_ip,
           task ? task->tls_version : 0,
           task ? task->extension_count : 0,
           (task && task->alpn[0]) ? task->alpn : "none",
           attck);
}
