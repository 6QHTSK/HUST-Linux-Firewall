//
// Created by csepsk on 2022/9/6.
//

#ifndef KERNEL_FIREWALL_FILTER_H
#define KERNEL_FIREWALL_FILTER_H
#include <linux/module.h>     /* Needed by all modules */
#include <linux/kernel.h>     /* Needed for KERN_INFO */
#include <linux/init.h>       /* Needed for the macros */
#include <linux/in.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <linux/slab.h>

#include "logging.h"

int seq_open_rule(struct inode *inode, struct file *file);
int update_rule(const char *buf);
int rule_matching(struct in_addr *src_ip, struct in_addr *dest_ip, __u8 protocol, __be16 src_port, __be16 dest_port);
void register_filter(void);

#endif //KERNEL_FIREWALL_FILTER_H
