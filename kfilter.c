#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marcin Franczyk");
MODULE_DESCRIPTION("Packets fitler");


static struct nf_hook_ops nfho; 

unsigned int net_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    // accept everything
    // in progress..
    return NF_ACCEPT;
};

static int filter_init(void) {
    printk(KERN_INFO "Initializing kfilter module");

    nfho.hook = net_hook;
    nfho.hooknum = NF_IP_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_hook(&nfho);

    printk(KERN_INFO "kfilter has started");
    return 0;
}

static void filter_exit(void) {
    nf_unregister_hook(&nfho);
    printk(KERN_INFO "filter modul has been removed!\n");
}

module_init(filter_init);
module_exit(filter_exit);
