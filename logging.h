//
// Created by csepsk on 2022/9/28.
//

#ifndef KERNEL_FIREWALL_LOGGING_H
#define KERNEL_FIREWALL_LOGGING_H

#include <linux/module.h>     /* Needed by all modules */
#include <linux/kernel.h>     /* Needed for KERN_INFO */
#include <linux/init.h>       /* Needed for the macros */
#include <linux/time.h>
#include <linux/rtc.h>
#include <linux/slab.h>

struct log_node{
    struct list_head node;
    ktime_t current_time;
    char msg[128];
};

#define LOG(list,fmt,...) sprintf(new_ ##list ()->msg, fmt , ##__VA_ARGS__ )

#define CONNECTION_LOG(fmt,...)  LOG(connection_log,fmt, ##__VA_ARGS__ )
#define RULE_LOG(fmt,...) LOG(rule_log,fmt, ##__VA_ARGS__)

#define LOG_SEQ_FILE_ENTRY_H(list) \
int seq_open_ ##list (struct inode*,struct file*); \
struct log_node* new_ ##list (void);               \
void clean_ ##list (void)

LOG_SEQ_FILE_ENTRY_H(connection_log);
LOG_SEQ_FILE_ENTRY_H(rule_log);

#endif //KERNEL_FIREWALL_LOGGING_H
