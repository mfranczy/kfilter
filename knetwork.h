#ifndef FILTER_PROTO
#define FILTER_PROTO

#ifndef __KERNEL__

#include <stdint.h>

#endif

// MAX_PAYLOAD must be <= 32k (for kernel >= 4.9)
// otherwise 16k
#define MAX_PORT_SIZE 100
#define MAX_RULES_SIZE 100
#define IF_NAME_SIZE 16

#pragma pack(push, 1)
struct rule {
    uint16_t port;
    uint32_t addr;
};

struct tcp_rules {
    struct rule r[MAX_RULES_SIZE];
    uint8_t rules_cnt;
};

struct udp_rules {
    struct rule r[MAX_RULES_SIZE];
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
};

// control structure, to check if userspace program can listen for incoming packets
struct service_ctl {
    pid_t pid;
    char msg[1024];
};
#pragma pack(pop)

#endif
