#ifndef METRICS
#define METRICS

#define TCP 6
#define INFLUXDB_PORT 8086
#define INFLUXDB_HOST "127.0.0.1"

#include "../knetwork.h"

struct metrics {
    char protocol[4];
    char interface[17];
    char ip[17];
    uint32_t port;
};

int connect_to_influxdb() {
    struct sockaddr_in sa;
    int sock_fd;

    memset(&sa, sizeof(sa), 0);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(INFLUXDB_PORT);
    if (inet_pton(AF_INET, INFLUXDB_HOST, &sa.sin_addr) < 1) {
        perror("Cannot translate INFLUXDB_HOST");
        return -1;
    }

    sock_fd = socket(AF_INET, SOCK_STREAM, TCP);
    if (sock_fd < 0) {
        perror("Cannot open socket");
        return -1;
    }

    if (connect(sock_fd, (struct sockaddr*)&sa, sizeof(struct sockaddr_in)) < 0) {
        perror("Err");
        return -1;
    }

    return sock_fd;
}

char buffer[1024];

int send_data(int fd, struct metrics* data) {
    char request[1024];
    char headers[44];
    char payload[980];
    char resp_buffer[1024];

    memset(request, 0, sizeof(request));
    memset(headers, 0, sizeof(headers));
    memset(payload, 0, sizeof(payload));
    memset(resp_buffer, 0, sizeof(resp_buffer));

    snprintf(payload, sizeof(resp_buffer),
        "packets,protocol=%s,interface=%s,ip=%s,port=%d value=1",
        data->protocol,
        data->interface,
        data->ip,
        data->port
    );
    snprintf(headers, sizeof(headers), "Host: localhost\nContent-Length: %d", strlen(payload));
    snprintf(request, sizeof(request), "POST /write?db=netfilter HTTP/1.1\n%s\n\n%s", headers, payload);

    if (write(fd, request, strlen(request)) < 1) {
        perror("Write err");
        return 1;
    }
    if (recv(fd, resp_buffer, sizeof(resp_buffer), 0) < 1) {
        perror("Err");
        return 1;
    }

    return 0;
}

#endif
