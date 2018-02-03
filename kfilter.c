#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>

#include "knetwork.h"

#define NETLINK_USER 31

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marcin Franczyk");
MODULE_DESCRIPTION("Packets filter");


static struct nf_hook_ops nfho;
static struct sock *nl_sk = NULL;
static struct subscriber sub;


unsigned int net_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr* iph = ip_hdr(skb);
    uint saddr = iph->saddr;
    uint daddr = iph->daddr;
    struct tcphdr* tcph = NULL;

    switch (iph->protocol) {
        case IPPROTO_UDP:
            //printk(KERN_INFO "kfilter: UDP %x %d", skb->tail, skb->len);
            break;
        case IPPROTO_TCP:
            tcph = tcp_hdr(skb);
            //printk(KERN_INFO "kfilter: S:%pI4:%d D:%pI4:%d", &saddr, ntohs(tcph->source), &daddr, ntohs(tcph->dest));
            break;
        default:
            //printk(KERN_INFO "kfilter: other protocol %d", iph->protocol);
            break;
    }

    return NF_ACCEPT;
};

static void read_conf(struct sk_buff *skb) {
    // set flag if someone is connected
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    int pid, msg_size, err;
    char *msg = "Registration confirmed";

    msg_size = strlen(msg);

    nlh = (struct nlmsghdr *)skb->data;
    printk(KERN_INFO "kfilter: New registration received: %s", (char *)nlmsg_data(nlh));
    pid = nlh->nlmsg_pid;

    if (sub.confirmed) {
        msg = "Registration refused";
        printk(KERN_INFO "kfilter: New registration refused for pid %d", pid);
    } else {
        printk(KERN_INFO "kfilter: New registration confirmed for pid %d", pid);
    }

    sub.confirmed = 1;

    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
        printk(KERN_ERR "kfilter: Unable to create new skb_buff");
        return;
    }
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0;
    strncpy(nlmsg_data(nlh), msg, msg_size);

    err = nlmsg_unicast(nl_sk, skb_out, pid);
    if (err < 0) {
        printk(KERN_ERR "kfilter: Could not send msg to userspace for pid: %d", pid);
    }

};

void send_data(void) {

};

static int filter_init(void) {
    struct netlink_kernel_cfg k_cfg = {
        .input = read_conf, 
    };

    printk(KERN_INFO "kfilter: Initializing kfilter module");

    nfho.hook = net_hook;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho);
    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &k_cfg);
    if (!nl_sk) {
        printk(KERN_ALERT "Error occured - unable to open NETLINK socket");
        return -EINVAL;
    }

    printk(KERN_INFO "kfilter: kfilter has started");
    return 0;
}

static void filter_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    netlink_kernel_release(nl_sk);
    printk(KERN_INFO "kfilter: has been removed");
}

module_init(filter_init);
module_exit(filter_exit);
