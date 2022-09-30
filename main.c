#include <linux/module.h>     /* Needed by all modules */
#include <linux/kernel.h>     /* Needed for KERN_INFO */
#include <linux/init.h>       /* Needed for the macros */
#include "nethooks.h"

///< The license type -- this affects runtime behavior 
MODULE_LICENSE("GPL");

///< The author -- visible when you use modinfo 
MODULE_AUTHOR("6QHTSK");

///< The description -- see modinfo 
MODULE_DESCRIPTION("A simple Linux Firewall");

///< The version of the module 
MODULE_VERSION("0.0.1");

static int __init kexec_test_init(void)
{
    printk(KERN_INFO "Loading firewall module...\n");
    register_net_hooks();
    return 0;
}

static void __exit kexec_test_exit(void)
{
    printk(KERN_INFO "Goodbye Mr.\n");
    unregister_net_hooks();
}

module_init(kexec_test_init);
module_exit(kexec_test_exit);

