//
// Created by csepsk on 2022/9/28.
//

#include "logging.h"

#define TIME_FMT "[UTC %d-%02d-%02d %02d:%02d:%02d] "
#define TIME_ARGS(tm)  (tm).tm_year+1900, (tm).tm_mon +1,(tm).tm_mday,(tm).tm_hour,(tm).tm_min,(tm).tm_sec

#define LOG_FILE_MACRO(list) \
static DEFINE_SPINLOCK( list## _spin);                                  \
static LIST_HEAD(list);                                                 \
struct log_node* new_ ##list (void){                                    \
    struct log_node* node = kzalloc(sizeof(struct log_node),GFP_ATOMIC);\
    node->current_time = ktime_get_real();                              \
    spin_lock_bh(& list## _spin);                                       \
    list_add_tail(&node->node,&(list));                                 \
    spin_unlock_bh(& list## _spin);                                     \
    return node;                                                        \
}                                                                       \
void clean_ ##list (void){  \
    struct list_head *node, *next_node; \
    spin_lock_bh(& list## _spin);   \
    list_for_each_safe(node,next_node,&(list)){ \
        struct log_node* log = list_entry(node,struct log_node,node);   \
        list_del(&log->node);   \
        kfree(node);    \
    }   \
    spin_unlock_bh(& list## _spin); \
}   \
static void*  list## _seq_start(struct seq_file *m, loff_t *pos){       \
    spin_lock_bh(& list## _spin);                                       \
    return seq_list_start(&(list),*pos);                                \
}                                                                       \
static void* list## _seq_next(struct seq_file *m, void *v,loff_t *pos){ \
    return seq_list_next(v,&(list),pos);                                \
}                                                                       \
static void list## _seq_stop(struct seq_file *m,void *v){               \
    spin_unlock_bh(& list## _spin);                                     \
}                                                                       \
static int list## _seq_show(struct seq_file *m, void *v){               \
    struct log_node *current_node = (struct log_node *)v;               \
    struct rtc_time tm = rtc_ktime_to_tm(current_node->current_time);   \
    seq_printf(m,TIME_FMT "%s\n", TIME_ARGS(tm), current_node->msg);    \
    return 0;                                                           \
}                                                                       \
static const struct seq_operations list## _seq_ops = {                  \
        .start = list## _seq_start,                                     \
        .next = list## _seq_next,                                       \
        .stop = list## _seq_stop,                                       \
        .show = list## _seq_show,                                       \
};                                                                      \
int seq_open_ ##list (struct inode *inode, struct file *file){          \
    return seq_open(file,& list## _seq_ops);                            \
}                            \

LOG_FILE_MACRO(connection_log)
LOG_FILE_MACRO(rule_log)