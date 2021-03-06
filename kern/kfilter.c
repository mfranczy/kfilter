#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/net_namespace.h>

#include "../knetwork.h"

#define NETLINK_USER 31



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marcin Franczyk");
MODULE_DESCRIPTION("Packets filter");


static struct nf_hook_ops nfho;
static struct sock *nl_sk = NULL;
static struct net_data data;
static struct tcp_rules t_rules = {
    .rules_cnt = 0
};
static struct udp_rules u_rules = {
    .rules_cnt = 0   
};

static pid_t upid = 0;


void log_info(char* str) {
    printk(KERN_INFO "kfilter: %s", str);
}

void log_err(char* str) {
    printk(KERN_ALERT "kfilter: %s", str);
}

int send_data(struct net_data* data) {
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    const int data_size = sizeof(*data);

    skb_out = nlmsg_new(data_size, 0);
    NETLINK_CB(skb_out).dst_group = 0;
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, data_size, 0);
    memcpy(nlmsg_data(nlh), data, data_size);
    if (nlmsg_unicast(nl_sk, skb_out, upid)) {
        return 1;
    }
    return 0;
};

void clean_rules(void) {
    uint8_t* r_cnt[] = {&u_rules.rules_cnt, &t_rules.rules_cnt};
    const uint8_t r_size = sizeof(r_cnt) / sizeof(uint8_t*);
    uint8_t i;
    for (i = 0; i < r_size; i++) {
        *r_cnt[i] = 0;
    }
    log_info("tcp and udp rules have been removed");
};

int packet_filter(uint32_t addr, uint16_t port, struct rule* filter_rules, uint8_t rules_cnt) {
    int i;
    for (i = 0; i < rules_cnt; i++, filter_rules++) {
        if (addr == filter_rules->addr && port == filter_rules->port) {
            return 1;
        }
    }
    return 0;
};

unsigned int net_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr* iph = ip_hdr(skb);
    struct ethhdr* eth = eth_hdr(skb);
    struct tcphdr* tcph = NULL;
    struct udphdr* udph = NULL;
    static bool exec_clean = false;
    bool drop_packet = false;

    if (!upid) {
        if (exec_clean) {
            clean_rules();
            exec_clean = false;
        }
        goto done;
    }

    // don't send packets from lo and docker interfaces
    if (strcmp(skb->dev->name, "lo") == 0 || strcmp(skb->dev->name, "docker0") == 0) {
        goto done;
    }

    memcpy(data.if_name, skb->dev->name, sizeof(data.if_name));
    memcpy(data.mac_s, eth->h_source, sizeof(data.mac_s));
    memcpy(data.mac_d, eth->h_dest, sizeof(data.mac_d));

    data.proto_id = iph->protocol;
    data.ttl = iph->ttl;
    data.s_addr = iph->saddr;
    data.d_addr = iph->daddr;

    switch (iph->protocol) {
        case IPPROTO_UDP:
            udph = udp_hdr(skb);
            data.s_port = ntohs(udph->source);
            data.d_port = ntohs(udph->dest);
            if (u_rules.rules_cnt && packet_filter(data.s_addr, data.s_port, u_rules.r, u_rules.rules_cnt)) {
                drop_packet = true;
            }
            break;
        case IPPROTO_TCP:
            tcph = tcp_hdr(skb);
            data.s_port = ntohs(tcph->source);
            data.d_port = ntohs(tcph->dest);
            if (t_rules.rules_cnt && packet_filter(data.s_addr, data.s_port, t_rules.r, t_rules.rules_cnt)) {
                drop_packet = true;
            }
            break;
    }

    if (send_data(&data)) {
        log_err("unable to send data to userspace");
        upid = 0;
        exec_clean = true;
    }

done:
    if (drop_packet) {
        return NF_DROP;
    }
    return NF_ACCEPT;
};

static int send_msg(pid_t pid, struct service_ctl* sctl) {
    struct nlmsghdr *nlh;
    struct sk_buff *skb;
    const int sctl_size = sizeof(*sctl);
 
    skb = nlmsg_new(sctl_size, 0);
    if (!skb) {
        log_err("unable to create new skb_buff");
        return 1;
    }

    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, sctl_size, 0);
    NETLINK_CB(skb).dst_group = 0;
    memcpy(nlmsg_data(nlh), sctl, sctl_size);
    return nlmsg_unicast(nl_sk, skb, pid);
}

static void reg_hook(struct sk_buff *skb) {
    struct service_ctl sctl;
    struct nlmsghdr *nlh;
    struct net_rules* rules;
    pid_t pid;

    nlh = (struct nlmsghdr*)skb->data;
    pid = nlh->nlmsg_pid;

    if (upid == pid) {
        rules = (struct net_rules*)NLMSG_DATA(nlh);
        memcpy(&t_rules, &rules->t_rules, sizeof(struct tcp_rules));
        memcpy(&u_rules, &rules->u_rules, sizeof(struct udp_rules));
    } else {
        // registration attempt
        if ((upid && send_msg(upid, &sctl) < 0) || !upid) {
            upid = pid;
        }
        sctl.pid = upid;
        if (send_msg(pid, &sctl) < 0) {
            log_err("could not send registration info back to the userspace client");
        }
    }
}

static int filter_init(void) {
    struct netlink_kernel_cfg k_cfg = {
        .input = reg_hook, 
    };

    log_info("initializing module...");
    nfho.hook = net_hook;
    nfho.hooknum = NF_INET_LOCAL_IN;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho);
    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &k_cfg);
    if (!nl_sk) {
        log_err("unable to open NETLINK socket");
        return -EINVAL;
    }

    log_info("module has been initialized");
    return 0;
}

static void filter_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    netlink_kernel_release(nl_sk);
    log_info("module has been removed");
}

module_init(filter_init);
module_exit(filter_exit);
