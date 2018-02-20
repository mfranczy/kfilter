#ifndef FILTER_PROTO
#define FILTER_PROTO

#ifndef __KERNEL__

#include <stdint.h>

#endif

// MAX_PAYLOAD must be <= 32k (for kernel >= 4.9)
// otherwise 16k
#define MAX_PORT_SIZE 100
#define MAX_RULES_SIZE 100
#define MAX_SERVICE_MSG_SIZE 1024
#define IF_NAME_SIZE 16

#pragma pack(push, 1)
struct rules {
    uint16_t ports[MAX_PORT_SIZE];
    uint8_t allocated_ports;
    uint32_t addr;
    char mac[6];
};

struct tcp_rules {
    struct rules r[MAX_RULES_SIZE];
    uint8_t rules_cnt;
};

struct udp_rules {
    struct rules r[MAX_RULES_SIZE];
    uint8_t rules_cnt;
};

// set rules for module to drop packets
struct net_rules {
    struct tcp_rules t_rules;
    struct udp_rules u_rules;
};

// packets data
struct net_data {
    // TODO:
    // - add alias
    // - add tx (+ dropped)
    // - add rx (+ dropped)
    char if_name[IF_NAME_SIZE];
    uint8_t proto_id;
    uint16_t ttl;
    char mac_s[6];
    char mac_d[6];
    uint32_t s_addr;
    uint32_t d_addr;
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
