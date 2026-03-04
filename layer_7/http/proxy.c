#define _POSIX_C_SOURCE 200809L

#include "proxy.h"
#include "../dns/dns.h"  // for blocklist functions and is_blocked()
#include <netdb.h>       // for getaddrinfo and struct addrinfo
#include <ctype.h>
#include <strings.h>

void start_proxy_server()
{
    // --- create TCP socket ---
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("Failed to create TCP socket");
        exit(1);
    }

    // --- SO_REUSEADDR ---
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("Failed to set SO_REUSEADDR");
        close(server_fd);
        exit(1);
    }

    // --- build server_addr struct ---
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(HTTP_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    // --- bind ---
    // man 2 bind — same as DNS
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Failed to bind TCP socket");
        close(server_fd);
        exit(1);
    }

    // --- listen ---
    if (listen(server_fd, MAX_PENDING_CONNECTIONS) < 0)
    {
        perror("Failed to listen on TCP socket");
        close(server_fd);
        exit(1);
    }

    printf("HTTP Proxy listening on 0.0.0.0:%d\n", HTTP_PORT);

    // --- accept loop ---
    while (1)
    {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);

        if (client_fd < 0)
        {
            perror("Failed to accept incoming connection");
            continue; // Try accepting the next connection
        }

        // --- allocate task ---
        http_task_t *task = calloc(1, sizeof(http_task_t));
        if (!task)
        {
            perror("Failed to allocate memory for HTTP task");
            close(client_fd);
            continue;
        }

        // --- fill in task fields ---
        task->client_socket = client_fd;
        task->client_addr = client_addr;

        // --- spawn thread ---
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_http_request, task) != 0)
        {
            perror("Failed to create HTTP task thread");
            free(task);
            close(client_fd);
            continue;
        }
        pthread_detach(thread_id);
    }
}

int recv_http_request(int client_fd, char *buffer, int buffer_size)
{
    int total = 0;

    while (total < buffer_size - 1) // leave space for null terminator
    {
        // --- recv from client ---
        ssize_t bytes = recv(client_fd, buffer + total, buffer_size - total - 1, 0);
        if (bytes == 0)
        {
            // client closed connection gracefully
            return -1;
        }
        else if (bytes < 0)
        {
            // actual error
            perror("Error receiving HTTP request");
            return -1;
        }
        
        total += bytes;
        buffer[total] = '\0'; // null terminate for string functions

        if (strstr(buffer, "\r\n\r\n") != NULL) // Found end of headers
            return total;
    }

    return -1;
}

int parse_http_request(char *buffer, http_task_t *task)
{
    char method[MAX_METHOD_LENGTH];
    char url[MAX_HOSTNAME_LENGTH + MAX_PATH_LENGTH]; 
    char version[MAX_VERSION_LENGTH];

    // --- parse request line ---
    if (sscanf(buffer, "%s %s %s", method, url, version) < 2)
    {
        fprintf(stderr, "Failed to parse HTTP request line\n");
        return -1;
    }

    // copy method into task->method
    strncpy(task->method, method, MAX_METHOD_LENGTH - 1);
    task->method[MAX_METHOD_LENGTH - 1] = '\0';

    // --- extract path from url ---
    // Case 1: Absolute URI (proxy request) — starts with "http://"
    if (strncmp(url, "http://", 7) == 0) // absolute URI (proxy request)
    {
        // skip "http://"
        char *hostname_ptr = &url[0] + 7;

        // find the first "/" after the host
        char *path_start = strchr(hostname_ptr, '/');
        if (!path_start)
            path_start = "/";

        strncpy(task->path, path_start, MAX_PATH_LENGTH - 1);
        task->path[MAX_PATH_LENGTH - 1] = '\0';
    }
    else // case 2: Origin Form (normal request) — starts with "/"
    {
        strncpy(task->path, url, MAX_PATH_LENGTH - 1);
        task->path[MAX_PATH_LENGTH - 1] = '\0';
    }

    // --- find the Host header ---
    char *host_start = NULL;
    char *line = buffer;
    while (line && *line)
    {
        char *next = strstr(line, "\r\n");
        if (strncasecmp(line, "Host:", 5) == 0)
        {
            host_start = line + 5;
            while (*host_start == ' ' || *host_start == '\t')
                host_start++;
            break;
        }
        if (!next) break;
        line = next + 2;
    }
    if (host_start == NULL)
    {
        fprintf(stderr, "Host header not found in HTTP request\n");
        return -1;
    }

    // --- extract hostname ---
    char *host_end = strstr(host_start, "\r\n"); // end of Host header line
    if (!host_end)
    {
        fprintf(stderr, "Malformed Host header in HTTP request\n");
        return -1;
    }
    
    // check host length and copy into task->hostname
    int host_len = host_end - host_start;
    if (host_len <= 0 || host_len >= MAX_HOSTNAME_LENGTH)
    {
        fprintf(stderr, "Invalid Host header length in HTTP request\n");
        return -1;
    }

    strncpy(task->hostname, host_start, host_len);
    task->hostname[host_len] = '\0'; // null terminate
    
    // --- strip port from host ---
    char *colon = strchr(task->hostname, ':');
    if (colon != NULL)
    {
        char *endptr;
        long port = strtol(colon + 1, &endptr, 10);
        
        if (*endptr == '\0' && port > 0 && port <= 65535)
            task->port = (int)port;
        else
            task->port = (strcasecmp(task->method, "CONNECT") == 0) ? 443 : 80;  // malformed port — use method default
        
        *colon = '\0';  // strip port from hostname
    }
    else
        task->port = (strcasecmp(task->method, "CONNECT") == 0) ? 443 : 80;

    // --- lowercase the host ---
    for (int i = 0; task->hostname[i]; i++)
        task->hostname[i] = (char)tolower((unsigned char)task->hostname[i]);

    return 0;
}

void send_403_response(int client_fd)
{
    const char *body = "<html><body><h1>Blocked by Pi-Blocker</h1></body></html>";
    int body_len = strlen(body);

    // build the full response with snprintf
    char response[HTTP_BUFFER_SIZE];
    int len = snprintf(response, sizeof(response),
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s", body_len, body);

    // send it
    if (send(client_fd, response, len, 0) < 0)
    {
        perror("Failed to send 403 response");
        return;
    }
}

void send_502_response(int client_fd)
{
    const char *body = "<html><body><h1>Bad Gateway</h1></body></html>";
    int body_len = strlen(body);

    char response[HTTP_BUFFER_SIZE];
    int len = snprintf(response, sizeof(response),
        "HTTP/1.1 502 Bad Gateway\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s", body_len, body);

    if (send(client_fd, response, len, 0) < 0)
    {
        perror("Failed to send 502 response");
        return;
    }
}

void forward_request(http_task_t *task, char *buffer, int buffer_len)
{
    // --- set up hints struct ---
    struct addrinfo hints;
    struct addrinfo *results;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // --- resolve hostname using task->port ---
    // use task->port instead of hardcoded "80"
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", task->port);

    int status = getaddrinfo(task->hostname, port_str, &hints, &results);
    if (status != 0)
    {
        fprintf(stderr, "Failed to resolve hostname %s: %s\n",
                task->hostname, gai_strerror(status));
        return;
    }

    // --- create upstream socket and connect ---
    int upstream_fd = -1;
    for (struct addrinfo *candidate = results; candidate != NULL; candidate = candidate->ai_next)
    {
        upstream_fd = socket(candidate->ai_family, candidate->ai_socktype,
                             candidate->ai_protocol);
        if (upstream_fd < 0)
            continue;

        if (connect(upstream_fd, candidate->ai_addr, candidate->ai_addrlen) == 0)
            break;

        close(upstream_fd);
        upstream_fd = -1;
    }

    freeaddrinfo(results);

    if (upstream_fd < 0)
    {
        perror("Failed to connect to upstream server");
        return;
    }

    // --- forward the original request ---
    ssize_t sent = send(upstream_fd, buffer, buffer_len, 0);
    if (sent < 0)
    {
        perror("Failed to send HTTP request to upstream server");
        close(upstream_fd);
        return;
    }

    // --- relay response back to client ---
    bool client_send_failed = false;
    while (!client_send_failed)
    {
        char relay_buf[HTTP_BUFFER_SIZE];
        ssize_t bytes = recv(upstream_fd, relay_buf, sizeof(relay_buf), 0);

        if (bytes < 0)
        {
            perror("Error receiving response from upstream server");
            break;
        }
        else if (bytes == 0)
            break; // upstream closed connection

        // handle partial sends
        ssize_t total_sent = 0;
        while (total_sent < bytes)
        {
            ssize_t s = send(task->client_socket, relay_buf + total_sent,
                             bytes - total_sent, 0);
            if (s < 0)
            {
                perror("Error sending response to client");
                client_send_failed = true;
                break;
            }
            total_sent += s;
        }
    }

    close(upstream_fd);
}

void* handle_http_request(void *arg)
{
    // cast arg — same pattern as handle_dns_request() in dns.c
    http_task_t *task = (http_task_t *)arg;

    // --- allocate buffer for receiving HTTP request ---
    char *buffer = calloc(HTTP_BUFFER_SIZE, 1);
    if (!buffer)
    {
        perror("Failed to allocate buffer for HTTP request");
        close(task->client_socket);
        free(task);
        return NULL;
    }
    
    // --- receive full HTTP request ---
    int request_len = recv_http_request(task->client_socket, buffer, HTTP_BUFFER_SIZE);
    if (request_len < 0)
    {
        // client closed connection or error occurred
        free(buffer);
        close(task->client_socket);
        free(task);
        return NULL;
    }

    // --- parse HTTP request into task fields ---
    if (parse_http_request(buffer, task) < 0)
    {
        free(buffer);
        close(task->client_socket);
        free(task);
        return NULL;
    }

    // --- check blocklist and route request ---
    if (is_blocked(task->hostname))
    {
        log_decision("BLOCKED", task);
        send_403_response(task->client_socket);
    }
    else if (strcasecmp(task->method, "CONNECT") == 0)
    {
        // HTTPS tunnel — RFC 7231 section 4.3.6
        log_decision("TUNNEL", task);
        handle_connect_tunnel(task);
    }
    else
    {
        // plain HTTP
        log_decision("FORWARDED", task);
        forward_request(task, buffer, request_len);
    }

    // --- final cleanup ---
    free(buffer);
    close(task->client_socket);
    free(task);

    return NULL;
}

void handle_connect_tunnel(http_task_t *task)
{
    // --- resolve hostname ---
    struct addrinfo hints;
    struct addrinfo *results;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // --- parse port from task->hostname if present ---
    char port_str[8];
    int ret = snprintf(port_str, sizeof(port_str), "%d", task->port);
    if (ret < 0 || (size_t)ret >= sizeof(port_str))
    {
        fprintf(stderr, "Error formatting port string\n");
        send_502_response(task->client_socket);
        return;
    }

    // --- resolve hostname using task->port ---
    int status = getaddrinfo(task->hostname, port_str, &hints, &results);
    if (status != 0)    {
        fprintf(stderr, "Failed to resolve hostname %s: %s\n",
                task->hostname, gai_strerror(status));
        send_502_response(task->client_socket);
        return;
    }

    // --- connect to real server ---
    int server_fd = -1;
    for (struct addrinfo *rp = results; rp != NULL; rp = rp->ai_next)
    {
        server_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (server_fd < 0)
            continue;

        if (connect(server_fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break; // success

        close(server_fd);
        server_fd = -1;
    }
    freeaddrinfo(results);

    // --- if connect failed → send 502 ---
    if (server_fd < 0)
    {
        perror("Failed to connect to upstream server for CONNECT tunnel");
        send_502_response(task->client_socket);
        return;
    }

    // --- send 200 Connection Established ---
    int send_status = send(task->client_socket, "HTTP/1.1 200 Connection Established\r\n\r\n", 39, 0);
    if (send_status < 0)
    {
        perror("Failed to send 200 Connection Established response");
        close(server_fd);
        return;
    }

    // --- relay bytes both directions ---
    char relay_buf[HTTP_BUFFER_SIZE];
    struct pollfd fds[2];
    fds[0].fd = task->client_socket;
    fds[0].events = POLLIN;
    fds[1].fd = server_fd;
    fds[1].events = POLLIN;

    while (1)
    {
        int client_activity = poll(fds, 2, 30000);

        if (client_activity < 0)
        {
            perror("poll error in CONNECT tunnel");
            break;
        }
        if (client_activity == 0)
            break;

        // --- browser → server ---
        if (fds[0].revents & POLLIN)
        {
            // recv from client
            ssize_t bytes = recv(task->client_socket, relay_buf, sizeof(relay_buf), 0);
            if (bytes < 0)
            {
                perror("Error receiving data from client in CONNECT tunnel");
                break;
            }
            else if (bytes == 0)
                break;

            // send to server
            int total_sent = 0;
            while (total_sent < bytes)
            {
                int send_bytes = send(server_fd, relay_buf + total_sent, bytes - total_sent, 0);
                if (send_bytes <= 0)
                {
                    perror("Error sending data to server in CONNECT tunnel");
                    goto tunnel_done;
                }
                total_sent += send_bytes;
            }
        }

        // --- server → browser ---
        if (fds[1].revents & POLLIN)
        {
            // recv from server
            ssize_t bytes = recv(server_fd, relay_buf, sizeof(relay_buf), 0);
            if (bytes < 0)
            {
                perror("Error receiving data from server in CONNECT tunnel");
                break;
            }
            else if (bytes == 0)
                break;

            // send to client
            int total_sent = 0;
            while (total_sent < bytes)
            {
                int send_bytes = send(task->client_socket, relay_buf + total_sent, bytes - total_sent, 0);
                if (send_bytes <= 0)
                {
                    perror("Error sending data to client in CONNECT tunnel");
                    goto tunnel_done;
                }
                total_sent += send_bytes;
            }
        }
    }

tunnel_done:
    // --- cleanup ---
    close(server_fd);
}

void log_decision(const char *action, http_task_t *task)
{
    // --- get timestamp ---
    time_t now = time(NULL);
    struct tm tm_buf;
    char timestamp[32];
    if (localtime_r(&now, &tm_buf) != NULL)
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_buf);
    else
        strncpy(timestamp, "unknown-time", sizeof(timestamp));

    // --- get client IP as string ---
    char client_ip[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &task->client_addr.sin_addr, client_ip, sizeof(client_ip)) == NULL)
        strncpy(client_ip, "unknown-ip", sizeof(client_ip));

    // --- print log line ---
    if (strcasecmp(task->method, "CONNECT") == 0)
    {
        printf("[%s] [LAYER_7] [HTTP] [%s] host=%s port=%d client=%s d3fend=D3-HTTPA attck=T1071.001\n",
                timestamp, action, task->hostname, task->port, client_ip);
    }
    else
    {
        printf("[%s] [LAYER_7] [HTTP] [%s] host=%s path=%s client=%s d3fend=D3-HTTPA attck=T1071.001\n",
                timestamp, action, task->hostname, task->path, client_ip);
    }
}
