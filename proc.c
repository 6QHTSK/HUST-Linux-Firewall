//
// Created by csepsk on 2022/9/6.
//
#include "proc.h"

#define DEFINE_SEQFILE_ENTRY(name,write_func)   \
static struct proc_dir_entry* proc_ ##name ;    \
static struct proc_ops file_fops_ ##name = {    \
    .proc_open  = seq_open_ ##name ,            \
    .proc_read  = seq_read,                     \
    .proc_write = write_func,                   \
    .proc_lseek = seq_lseek,                    \
    .proc_release = seq_release                 \
}

#define DEFINE_SEQFILE_ENTRY_R(name) DEFINE_SEQFILE_ENTRY(name,NULL)

#define REGIST_SEQFILE_ENTRY(name,parent_node) proc_ ##name = proc_create( #name ,0666,parent_node,& file_fops_ ##name)

#define UNREGIST_SEQFILE_ENTRY(name) proc_remove(proc_ ##name )

static ssize_t proc_update_rules(struct file *file,const char __user *usr_buf, size_t count, loff_t *pos){
    ssize_t c,ret;
    static char kernel_buf[PROCBUFF];
    c = simple_write_to_buffer(kernel_buf,PROCBUFF,pos,usr_buf,count);
    ret = update_rule(kernel_buf);
    if(ret != 0)
        return ret;
    printk(KERN_INFO "UPDATING RULES!\n");
    return c;
}

static ssize_t proc_update_nat(struct file *file,const char __user *usr_buf, size_t count, loff_t *pos){
    ssize_t c;
    static char kernel_buf[PROCBUFF];
    c = simple_write_to_buffer(kernel_buf,PROCBUFF,pos,usr_buf,count);
    update_nat(kernel_buf);
    printk(KERN_INFO "UPDATING RULES!\n");
    return c;
}

static ssize_t proc_clean_connection_log(struct file *file,const char __user *usr_buf, size_t count, loff_t *pos){
    printk("Clean Connection Log");
    clean_connection_log();
    return count;
}

static struct proc_dir_entry *proc_firewall;
DEFINE_SEQFILE_ENTRY(rule,proc_update_rules);
DEFINE_SEQFILE_ENTRY(nat,proc_update_nat);
DEFINE_SEQFILE_ENTRY_R(tcp_connection);
DEFINE_SEQFILE_ENTRY_R(udp_connection);
DEFINE_SEQFILE_ENTRY_R(icmp_connection);

DEFINE_SEQFILE_ENTRY(connection_log,proc_clean_connection_log);
DEFINE_SEQFILE_ENTRY_R(rule_log);


void register_proc_file(void){
    proc_firewall = proc_mkdir("firewall",NULL);
    REGIST_SEQFILE_ENTRY(rule,proc_firewall);
    REGIST_SEQFILE_ENTRY(nat,proc_firewall);
    REGIST_SEQFILE_ENTRY(tcp_connection,proc_firewall);
    REGIST_SEQFILE_ENTRY(udp_connection,proc_firewall);
    REGIST_SEQFILE_ENTRY(icmp_connection,proc_firewall);
    REGIST_SEQFILE_ENTRY(connection_log,proc_firewall);
    REGIST_SEQFILE_ENTRY(rule_log,proc_firewall);
}

void unregister_proc_file(void){
    UNREGIST_SEQFILE_ENTRY(rule);
    UNREGIST_SEQFILE_ENTRY(nat);
    UNREGIST_SEQFILE_ENTRY(connection_log);
    UNREGIST_SEQFILE_ENTRY(rule_log);
    UNREGIST_SEQFILE_ENTRY(tcp_connection);
    UNREGIST_SEQFILE_ENTRY(udp_connection);
    UNREGIST_SEQFILE_ENTRY(icmp_connection);
    proc_remove(proc_firewall);
}
