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

    // --- no bind, no listen, no accept ---
    // --- passive sniffing ---
    printf("TLS Inspector listening on all interfaces (port 443 traffic)\n");
    printf("D3FEND: D3-TLSIC | ATT&CK: T1573\n");


    // --- capture loop ---
    while (1)
    {
        // allocate task for this packet
        // same calloc pattern as DNS and HTTP
        tls_task_t *task = calloc(1, sizeof(tls_task_t));
        if (!task) { continue; }

        // receive raw packet into task->buffer
        socklen_t addr_len = sizeof(task->src_addr);
        task->packet_len = recvfrom(raw_fd, task->buffer, TLS_BUFFER_SIZE, 0,
                                    (struct sockaddr*)&task->src_addr, &addr_len);
        if (task->packet_len < 0)
        {
            free(task);
            continue;
        }

        // --- filter for port 443 only ---
        struct ip_hdr *ip_header = (struct ip_hdr *)task->buffer;
        size_t ip_hdr_len = (ip_header->version_ihl & 0x0F) * 4;
        
        struct tcp_hdr *tcp_header = (struct tcp_hdr *)(task->buffer + ip_hdr_len);
        uint16_t dest_port = ntohs(tcp_header->dst_port);

        if (dest_port != HTTPS_PORT)
        {
            free(task);
            continue;
        }
        
        // --- check if this is a TLS ClientHello ---
        size_t tcp_hdr_len = ((tcp_header->data_offset & 0xF0) >> 4) * 4;
        if (!(is_tls_client_hello(task->buffer + ip_hdr_len + tcp_hdr_len,
                              task->packet_len - ip_hdr_len - tcp_hdr_len)))
        {
            free(task);
            continue;
        }

        // --- spawn thread ---
        // same pthread_create + pthread_detach pattern as DNS and HTTP
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
    if (len < TLS_RECORD_HEADER_SIZE + TLS_HANDSHAKE_HEADER_SIZE)
        return 0;

    // --- check content type ---
    struct tls_record_hdr *record_hdr = (struct tls_record_hdr *)buffer;
    if (record_hdr->content_type != TLS_CONTENT_TYPE_HANDSHAKE)
        return 0;

    // --- check handshake type ---
    struct tls_handshake_hdr *handshake_hdr = (struct tls_handshake_hdr *)(buffer + TLS_RECORD_HEADER_SIZE);
    if (handshake_hdr->handshake_type != TLS_HANDSHAKE_CLIENT_HELLO)
        return 0;

    return 1; // it's a ClientHello
}

int extract_sni(unsigned char *buffer, int len,
                char *hostname, int hostname_len)
{
    // --- set up pointer to start of ClientHello body ---
    // skip TLS record header (5 bytes) + handshake header (4 bytes)
    int pos = TLS_RECORD_HEADER_SIZE + TLS_HANDSHAKE_HEADER_SIZE;

    // --- bounds check helper ---
    #define CHECK_BOUNDS(bytes_needed) \
    do { \
        if (pos + (bytes_needed) > len) \
            return -1; \
    } while (0)

    // --- skip fixed size fields ---
    // legacy_version: 2 bytes
    CHECK_BOUNDS(2);
    pos += 2;

    // random: always exactly 32 bytes (RFC 8446 section 4.1.2)
    CHECK_BOUNDS(32);
    pos += 32;

    // --- skip session_id ---
    // read 1 byte length, then skip that many bytes
    CHECK_BOUNDS(1);
    uint8_t session_id_len = buffer[pos];
    CHECK_BOUNDS(1 + session_id_len);
    pos += 1 + session_id_len;

    // --- skip cipher_suites ---
    // read 2 byte length (big endian!), then skip that many bytes
    // use ntohs() or manual shift: (buffer[pos] << 8) | buffer[pos+1]
    CHECK_BOUNDS(2);
    uint16_t cipher_suites_len = ntohs(*(uint16_t *)(buffer + pos));
    CHECK_BOUNDS(2 + cipher_suites_len);
    pos += 2 + cipher_suites_len;

    // --- skip compression methods ---
    // read 1 byte length, then skip that many bytes
    CHECK_BOUNDS(1);
    uint8_t compression_len = buffer[pos];
    CHECK_BOUNDS(1 + compression_len);
    pos += 1 + compression_len;

    // --- read extensions length ---
    // 2 bytes, big endian
    CHECK_BOUNDS(2);
    uint16_t extensions_len = ntohs(*(uint16_t *)(buffer + pos));
    pos += 2;
    CHECK_BOUNDS(extensions_len);

    // extensions_end marks where extensions stop
    int extensions_end = pos + extensions_len;

    // --- walk through extensions looking for SNI ---
    // each extension looks like:
    //   extension_type   2b
    //   extension_length 2b
    //   extension_data   variable

    while (pos + 4 <= extensions_end && pos + 4 <= len)
    {
        // read extension type (2 bytes big endian)
        uint16_t ext_type = ntohs(*(uint16_t *)(buffer + pos));
        pos += 2;

        // read extension length (2 bytes big endian)
        uint16_t ext_len = ntohs(*(uint16_t *)(buffer + pos));
        pos += 2;
        if (pos + ext_len > extensions_end || pos + ext_len > len) return -1;

        // is this the SNI extension?
        if (ext_type == TLS_EXT_SNI)
        {
            // SNI extension data structure:
            //   server_name_list_length  2b
            //   name_type                1b, 0x00 = host_name
            //   name_length              2b
            //   name                     variable, the actual hostname

            CHECK_BOUNDS(2);
            pos += 2; // skip server_name_list_length

            CHECK_BOUNDS(1);
            uint8_t name_type = buffer[pos];
            pos += 1;

            // only handle host_name type (TLS_SNI_HOST_NAME = 0x00)
            if (name_type != TLS_SNI_HOST_NAME) return -1;

            CHECK_BOUNDS(2);
            uint16_t name_len = ntohs(*(uint16_t *)(buffer + pos));
            pos += 2;

            // bounds check before copying
            CHECK_BOUNDS(name_len);

            // copy hostname into output buffer
            // don't copy more than hostname_len - 1 bytes
            // null terminate after copying
            int copy_len = (name_len < hostname_len - 1) ? name_len : (hostname_len - 1);
            memcpy(hostname, buffer + pos, copy_len);
            hostname[copy_len] = '\0';

            // lowercase it — same pattern as dns.c and proxy.c
            for (int i = 0; hostname[i]; i++)
                hostname[i] = tolower(hostname[i]);

            return 0; // success
        }
        else
            pos += ext_len; // not the SNI extension — skip past it
    }
    return -1; // SNI extension not found
}

void* handle_tls_packet(void *arg)
{
    // cast arg — same pattern as every other thread function
    tls_task_t *task = (tls_task_t *)arg;

    // --- find TLS payload within raw packet ---
    // extract IP header and TCP header to calculate offsets
    struct ip_hdr *ip_header = (struct ip_hdr *)task->buffer;
    size_t ip_hdr_len = (ip_header->version_ihl & 0x0F) * 4;

    struct tcp_hdr *tcp_header = (struct tcp_hdr *)(task->buffer + ip_hdr_len);
    size_t tcp_hdr_len = ((tcp_header->data_offset & 0xF0) >> 4) * 4;

    unsigned char *tls_start = task->buffer + ip_hdr_len + tcp_hdr_len;
    int tls_len = task->packet_len - ip_hdr_len - tcp_hdr_len;

    // --- check minimum size ---
    if (tls_len < TLS_RECORD_HEADER_SIZE + TLS_HANDSHAKE_HEADER_SIZE)
    {
        free(task);
        return NULL;
    }

    // --- verify it's a ClientHello ---
    if (!is_tls_client_hello(tls_start, tls_len))
    {
        free(task);
        return NULL;
    }

    // --- extract SNI ---
    if (extract_sni(tls_start, tls_len, task->hostname, TLS_MAX_HOSTNAME_LEN) < 0)
    {
        log_decision("ALLOWED (no SNI)", task);
        free(task);
        return NULL;
    }

    // --- check blocklist ---
    // reuse is_blocked() from dns.c
    if (is_blocked(task->hostname))
    {
        // log blocked
        // NOTE: you can't send a response — this is passive
        // log the alert and optionally feed to Layer 4 firewall
        log_decision("BLOCKED", task);
    }
    else
    {
        log_decision("ALLOWED", task);
    }

    // --- cleanup ---
    free(task);
    return NULL;
}

void log_decision(const char *action, tls_task_t *task)
{
    // same pattern as Layer 7 log_decision()
    // get timestamp with time() → localtime() → strftime()

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    // get source IP string
    // task->src_addr.sin_addr — same inet_ntoa() call as dns.c
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &task->src_addr.sin_addr, src_ip, sizeof(src_ip));

    // print structured log line matching LAYER_6.md format:
    // [TIMESTAMP] [LAYER_6] [TLS] [ACTION] host=X src=X d3fend=D3-TLSIC attck=T1573
    printf("[%s] [LAYER_6] [TLS] [%s] host=%s src=%s d3fend=D3-TLSIC attck=T1573\n", timestamp, action, task->hostname, src_ip);
}
