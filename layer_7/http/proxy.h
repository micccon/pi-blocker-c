#ifndef PROXY_H
#define PROXY_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#include <netdb.h>

// --- includes ---
// think about what each function will need
// hint: you need threading, sockets, string ops, and time for logging
// look at your dns.h for inspiration on what you included there


// --- constants ---
#define HTTP_BUFFER_SIZE 8192
#define HTTP_PORT 8080
#define MAX_HOSTNAME_LENGTH 253
#define MAX_PATH_LENGTH 2048
#define MAX_PENDING_CONNECTIONS 10
#define MAX_METHOD_LENGTH 8
#define MAX_VERSION_LENGTH 16


// --- task struct ---
typedef struct {
    int client_socket;                      // The socket fd to talk back to the client
    struct sockaddr_in client_addr;         // Who sent the request (for logging)
    char method[MAX_METHOD_LENGTH];         // HTTP method (e.g., "GET", "POST")
    char hostname[MAX_HOSTNAME_LENGTH];     // Hostname from the HTTP request
    char path[MAX_PATH_LENGTH];             // Path from the HTTP request
} http_task_t;

// --- function signatures ---
// implement these in proxy.c

// sets up TCP socket and runs the accept loop forever
void  start_proxy_server();

// reads from TCP stream until \r\n\r\n is found
// returns total bytes read, or -1 on error
int   recv_http_request(int client_fd, char *buffer, int buffer_size);

// parses raw HTTP bytes into the task struct fields
// returns 0 on success, -1 on failure
int   parse_http_request(char *buffer, http_task_t *task);

// sends a 403 Forbidden HTTP response to the client
void  send_403_response(int client_fd);

// resolves host, connects to real server, relays request and response
void  forward_http_request(http_task_t *task, char *buffer, int buffer_len);

// thread entry point — orchestrates all the above
void* handle_http_request(void *arg);

// writes a structured log line to stdout (and optionally a file)
void  log_decision(const char *action, http_task_t *task);

#endif