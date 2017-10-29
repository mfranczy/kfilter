#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

#include <net/net_namespace.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marcin Franczyk");
MODULE_DESCRIPTION("Packets filter");


static struct nf_hook_ops nfho; 


unsigned int net_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    // accept everything
    // in progress..
    printk(KERN_INFO "Test: protocol %d", skb->protocol);
    return NF_ACCEPT;
};

static int filter_init(void) {
    printk(KERN_INFO "Initializing kfilter module");

    nfho.hook = net_hook;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho);

    printk(KERN_INFO "kfilter has started");
    return 0;
}

static void filter_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "kfilter has been removed");
}

module_init(filter_init);
module_exit(filter_exit);
