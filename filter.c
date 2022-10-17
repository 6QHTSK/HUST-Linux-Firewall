//
// Created by csepsk on 2022/9/6.
//
#include "filter.h"

struct firewall_rule{
    struct list_head list_node;
    struct in_addr src_ip, dest_ip;
    u8 src_mask,dest_mask;
    __be16 src_port,dest_port;
    union {
        struct{
            u8 tcp:1;
            u8 udp:1;
            u8 icmp:1;
            u8 permit:1;
            u8 src_port_spec:1;
            u8 dest_port_spec:1;
            u8 padding:2;
        };
        u8 value;
    }flag;
};

#define MASK(i) htonl(~0ul << (32 - (i)))

static DEFINE_SPINLOCK(rule_spin);
static LIST_HEAD(rule);
static u32 firewall_rule_cnt;

static u8 protocol_match(int protocol, struct firewall_rule* pRule){
    switch(protocol){
        case IPPROTO_TCP:
            return pRule->flag.tcp;
        case IPPROTO_UDP:
            return pRule->flag.udp;
        case IPPROTO_ICMP:
            return pRule->flag.icmp;
        default:
            return 0;
    }
}

static void* rule_seq_start(struct seq_file *m, loff_t *pos){
    spin_lock_bh(&rule_spin);
    firewall_rule_cnt = 1;
    return seq_list_start(&rule,*pos);
}

static void* rule_seq_next(struct seq_file *m, void *v,loff_t *pos){
    return seq_list_next(v,&rule,pos);
}

static void rule_seq_stop(struct seq_file *m,void *v){
    spin_unlock_bh(&rule_spin);
}

static int rule_seq_show(struct seq_file *m, void *v){
    struct firewall_rule *current_rule = (struct firewall_rule *)v;
    seq_printf(m,"%d %pI4/%hhu %pI4/%hhu ",
           firewall_rule_cnt++, &current_rule->src_ip,current_rule->src_mask,
           &current_rule->dest_ip,current_rule->dest_mask);
    current_rule->flag.src_port_spec ? seq_printf(m," %hu ",current_rule->src_port) : seq_puts(m," * ");
    current_rule->flag.dest_port_spec ? seq_printf(m,"%hu",current_rule->dest_port) : seq_puts(m," * ");
    seq_printf(m," %s %s %s %s\n",
               current_rule->flag.tcp ? "TCP" : "",
               current_rule->flag.udp ? "UDP" : "",
               current_rule->flag.icmp ? "ICMP" : "",
               current_rule->flag.permit ? "PERMIT" : "DENY");
    return 0;
}

static const struct seq_operations rule_seq_ops = {
        .start = rule_seq_start,
        .next = rule_seq_next,
        .stop = rule_seq_stop,
        .show = rule_seq_show,
};

int seq_open_rule(struct inode *inode, struct file *file){
    return seq_open(file,&rule_seq_ops);
}

static inline void print_rule(const char* msg, struct firewall_rule* target){
    RULE_LOG("%s %pI4/%hhu %pI4/%hhu %d %d %s %s %s %s",
             msg, &target->src_ip,target->src_mask,
             &target->dest_ip,target->dest_mask,
             target->flag.src_port_spec ? ntohs(target->src_port) : -1,
             target->flag.dest_port_spec ? ntohs(target->dest_port) : -1,
             target->flag.tcp ? "TCP" : "",
             target->flag.udp ? "UDP" : "",
             target->flag.icmp ? "ICMP" : "",
             target->flag.permit ? "PERMIT" : "DENY"
             );
}

static int modify_rule(const char* buf,struct firewall_rule* target){
    u32 src_ip,dest_ip;
    u16 src_port,dest_port;
    u8 src_mask,dest_mask,flag;
    if( sscanf(buf,"%*x %*d %x %hhu %x %hhu %hx %hx %hhx",
               &src_ip,&src_mask,&dest_ip,&dest_mask,&src_port,&dest_port,&flag) < 7){
        return -EIO;
    }
    target->src_ip.s_addr = htonl(src_ip);
    target->src_mask = src_mask;
    target->dest_ip.s_addr = htonl(dest_ip);
    target->dest_mask = dest_mask;
    target->src_port = htons(src_port);
    target->dest_port = htons(dest_port);
    target->flag.value = flag;
    return 0;
}

static int add_rule(const char* buf, struct firewall_rule* target){
    struct firewall_rule* new_rule = kzalloc(sizeof(struct firewall_rule),GFP_ATOMIC);
    int ret;
    ret = modify_rule(buf,new_rule);
    if(ret != 0) return ret;
    list_add(&new_rule->list_node,&target->list_node);
    print_rule("ADD RULE",new_rule);
    return 0;
}

static inline void del_rule(struct firewall_rule* target){
    print_rule("DELETE RULE",target);
    list_del(&target->list_node);
    kfree(target);
}

static bool deny_log = false;

static inline int switch_deny_log(const char* buf){
    int status;
    if( sscanf(buf,"%*x %*d %d",&status) ){
        return -EIO;
    }
    deny_log = status != 0 ? true : false;
    printk("MODIFY deny_log to %d\n",deny_log);
    return 0;
}

// 操作对象默认为链表头（第一条规则）
int update_rule(const char *buf) {
    u8 operation;
    short target;
    struct firewall_rule* target_rule;
    int ret = -EFAULT;
    spin_lock_bh(&rule_spin);
    sscanf(buf,"%hhx %hd",&operation,&target);
    list_for_each_entry(target_rule, &rule, list_node){
        if(target-- <= 1)
            break;
    }
    switch(operation){
        case 0:
            ret = add_rule(buf,target_rule); break;
        case 1:
            if(list_is_head(&target_rule->list_node,&rule)) break;
            del_rule(target_rule); break;
        case 2:
            if(list_is_head(&target_rule->list_node,&rule)) break;
            print_rule("MODIFY RULE FROM",target_rule);
            ret = modify_rule(buf,target_rule);
            print_rule("MODIFY RULE TO",target_rule);
            break;
        case 3:
            ret = switch_deny_log(buf);break;
        default:;
    }
    spin_unlock_bh(&rule_spin);
    return ret;
}

int rule_matching(struct in_addr *src_ip, struct in_addr *dest_ip, __u8 protocol, __be16 src_port, __be16 dest_port){
    struct firewall_rule *current_rule;
    spin_lock_bh(&rule_spin);
    list_for_each_entry(current_rule, &rule, list_node) {
        //printk("%x %x %x %x %d %d",(src_ip->s_addr & MASK(current_rule->src_mask)) , current_rule->src_ip.s_addr,  (dest_ip->s_addr & MASK(current_rule->dest_mask)) , current_rule->dest_ip.s_addr , protocol_match(protocol,current_rule) , current_rule->flag.permit);
        if ((src_ip->s_addr & MASK(current_rule->src_mask)) == current_rule->src_ip.s_addr
        && (dest_ip->s_addr & MASK(current_rule->dest_mask)) == current_rule->dest_ip.s_addr
        && protocol_match(protocol,current_rule)) {
            if((current_rule->flag.src_port_spec && src_port != current_rule->src_port)
            || (current_rule->flag.dest_port_spec && dest_port != current_rule->dest_port))
                continue;
            //printk("Matched!");
            spin_unlock_bh(&rule_spin);
            if(deny_log && !current_rule->flag.permit){
                CONNECTION_LOG("DENY A %s CONNECTION %pI4:%d => %pI4:%d",
                               protocol == IPPROTO_TCP ? "TCP" : (protocol == IPPROTO_UDP ? "UDP" : (protocol == IPPROTO_ICMP ? "ICMP" : "UNKNOWN")),
                               src_ip,ntohs(src_port),
                               dest_ip,ntohs(dest_port));
            }
            return current_rule->flag.permit;
        }
    }
    spin_unlock_bh(&rule_spin);
    return 0;
}

void inline register_filter(void){}
