#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/net_namespace.h>

#include "knetwork.h"

#define NETLINK_USER 31


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marcin Franczyk");
MODULE_DESCRIPTION("Packets filter");


static struct nf_hook_ops nfho;
static struct sock *nl_sk = NULL;
struct net_data data;

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
    int err, data_size = sizeof(*data);

    skb_out = nlmsg_new(data_size, 0);
    NETLINK_CB(skb_out).dst_group = 0;
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, data_size, 0);
    memcpy(nlmsg_data(nlh), data, data_size);
    err = nlmsg_unicast(nl_sk, skb_out, upid);
    if (err) {
        return 1;
    } else {
        return 0;
    }
};

unsigned int net_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    // filter only incoming packets
    // filter outcoming packets / maybe different functions?
    struct iphdr* iph = ip_hdr(skb);
    uint saddr = iph->saddr;
    uint daddr = iph->daddr;
    struct tcphdr* tcph = NULL;
    int err;

    switch (iph->protocol) {
        case IPPROTO_UDP:
            //printk(KERN_INFO "kfilter: UDP %x %d", skb->tail, skb->len);
            break;
        case IPPROTO_TCP:
            tcph = tcp_hdr(skb);
            if (upid) {
                err = send_data(&data);
                if (err) {
                    log_err("unable to send data to userspace");
                    upid = 0;
                }
            }
            //printk(KERN_INFO "kfilter: S:%pI4:%d D:%pI4:%d", &saddr, ntohs(tcph->source), &daddr, ntohs(tcph->dest));
            break;
        default:
            //printk(KERN_INFO "kfilter: other protocol %d", iph->protocol);
            break;
    }

    return NF_ACCEPT;
};

static void reg_hook(struct sk_buff *skb) {
    struct service_ctl sctl;
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    pid_t pid;
    int sctl_size, err;

    nlh = (struct nlmsghdr*)skb->data;
    pid = nlh->nlmsg_pid;
    if (upid) {
        sctl.pid = upid;
        // strncpy
        log_info("registration for new pid refused");
    } else {
        upid = pid;
        sctl.pid = pid;
        log_info("registration for new pid accepted");
    }

    sctl_size = sizeof(sctl);
    skb_out = nlmsg_new(sctl_size, 0);
    if (!skb_out) {
        log_err("unable to create new skb_buff");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, sctl_size, 0);
    NETLINK_CB(skb_out).dst_group = 0;
    memcpy(nlmsg_data(nlh), &sctl, sctl_size);
    err = nlmsg_unicast(nl_sk, skb_out, pid);
    if (err < 0) {
        log_err("could not send registration info back to the userspace client");
    }

}

static int filter_init(void) {
    struct netlink_kernel_cfg k_cfg = {
        .input = reg_hook, 
    };

    log_info("initializing module...");

    nfho.hook = net_hook;
    nfho.hooknum = NF_INET_PRE_ROUTING;
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
