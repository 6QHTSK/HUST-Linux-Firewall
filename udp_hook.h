//
// Created by csepsk on 2022/9/2.
//

#ifndef KERNEL_FIREWALL_UDP_HOOK_H
#define KERNEL_FIREWALL_UDP_HOOK_H
#include <linux/module.h>     /* Needed by all modules */
#include <linux/kernel.h>     /* Needed for KERN_INFO */
#include <linux/init.h>       /* Needed for the macros */
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/in.h>

#include "logging.h"
#include "utils.h"
#include "filter.h"

void register_net_hook_udp_hook(void);
void unregister_net_hook_udp_hook(void);
int check_udp_packet(struct sk_buff *);
int seq_open_udp_connection(struct inode *inode, struct file *file);

#endif //KERNEL_FIREWALL_UDP_HOOK_H
