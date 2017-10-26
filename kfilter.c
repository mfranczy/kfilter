#include <linux/init.h>
#include <linux/module.h>


static int filter_init(void) {
    printk(KERN_INFO "filter has been initialized successfuly!\n");
    return 0;
}

static void filter_exit(void) {
    printk(KERN_INFO "filter modul has been removed!\n");
}

module_init(filter_init);
module_exit(filter_exit);
