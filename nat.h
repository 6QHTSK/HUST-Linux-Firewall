//
// Created by csepsk on 2022/9/29.
//

#ifndef KERNEL_FIREWALL_CMAKE_NAT_H
#define KERNEL_FIREWALL_CMAKE_NAT_H

#include <linux/module.h>     /* Needed by all modules */
#include <linux/kernel.h>     /* Needed for KERN_INFO */
#include <linux/init.h>       /* Needed for the macros */
#include <linux/rbtree.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "logging.h"
#include "utils.h"

void nat_lan2wan(struct sk_buff*);
void nat_wan2lan(struct sk_buff*);
int update_nat(const char *);
int seq_open_nat(struct inode *, struct file *);

#endif //KERNEL_FIREWALL_CMAKE_NAT_H
