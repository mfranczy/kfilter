#ifndef FILTER_PROTO
#define FILTER_PROTO

#ifndef __KERNEL__

#include <stdint.h>

#endif

#pragma pack(push, 1)
// MAX_PAYLOAD must be <= 32k (for kernel >= 4.9)
// otherwise 16k
#define MAX_PORT_SIZE 100
#define MAX_ADDR_SIZE 100
#define MAX_SERVICE_MSG_SIZE 1024

struct tcp_rules { 
    uint16_t ports[MAX_PORT_SIZE];  // allocate this dynamically?
    uint32_t addr[MAX_ADDR_SIZE][4];
    char mac[6];
};

struct udp_rules {
    uint16_t ports[MAX_PORT_SIZE];
    uint32_t addr[MAX_ADDR_SIZE][4];
    char mac[6];
};

// set rules for module to drop packets
struct net_rules {
    struct tcp_rules t_rules;
    struct udp_rules u_rules;
};

// packets data
struct net_data {
    uint8_t proto_id;
    uint16_t ttl;
    char if_name[255];
    char mac_s[6];
    char mac_d[6];
    uint32_t s_addr[4];
    uint32_t d_addr[4];
    uint16_t s_port;
    uint16_t d_port;
    uint64_t len;
    char payload[15625];
    char extra_info[255];
};

// control structure, to check if userspace program can listen for incoming packets
struct service_ctl {
    int pid;
    char msg[MAX_SERVICE_MSG_SIZE];
};
#pragma pack(pop)

#endif
