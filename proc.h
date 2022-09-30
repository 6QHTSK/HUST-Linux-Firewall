//
// Created by csepsk on 2022/9/6.
//

#ifndef KERNEL_FIREWALL_PROC_H
#define KERNEL_FIREWALL_PROC_H
#include <linux/module.h>     /* Needed by all modules */
#include <linux/kernel.h>     /* Needed for KERN_INFO */
#include <linux/init.h>       /* Needed for the macros */
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include <linux/seq_file.h>

#include "logging.h"
#include "filter.h"
#include "udp_hook.h"
#include "icmp_hook.h"
#include "tcp_hook.h"
#include "nat.h"

// 分配内存大小4096B
#define PROCBUFF 4096
void register_proc_file(void);
void unregister_proc_file(void);
#endif //KERNEL_FIREWALL_PROC_H
