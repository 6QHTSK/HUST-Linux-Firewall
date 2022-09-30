//
// Created by csepsk on 2022/9/29.
//

#include "nat.h"

struct nat_rule {
    struct list_head list_node;
    struct sockaddr_in lan, wan;
    union{
        struct{
            u8 tcp:1;
            u8 udp:1;
            u8 debug_log:1;
            u8 padding:5;
        };
        u8 value;
    }flag;
};

static DEFINE_SPINLOCK(nat_spin);
static LIST_HEAD(nat);

static u8 protocol_match(int protocol, struct nat_rule* pRule){
    switch(protocol){
        case IPPROTO_TCP:
            return pRule->flag.tcp;
        case IPPROTO_UDP:
            return pRule->flag.udp;
        default:
            return 0;
    }
}

static struct nat_rule* rule_find_lan(struct sockaddr_in *lan, int protocol){
    struct nat_rule *current_rule;
    spin_lock_bh(&nat_spin);
    list_for_each_entry(current_rule, &nat, list_node) {
        if (protocol_match(protocol,current_rule) && sockaddr_in_cmp(lan,&current_rule->lan) == 0) {
            spin_unlock_bh(&nat_spin);
            return current_rule;
        }
    }
    spin_unlock_bh(&nat_spin);
    return NULL;
}

// 内网到外网，改源地址
void nat_lan2wan(struct sk_buff *skb){
    struct iphdr *iph;
    struct sockaddr_in addr = {.sin_family=AF_INET};
    if(!skb)
        return;
    iph = ip_hdr(skb);
    if(iph->protocol == IPPROTO_TCP){
        struct tcphdr* tcph = (void*) iph + iph->ihl * 4; //查找TCP头;
        struct nat_rule* rule;
        memcpy(&addr.sin_addr,&iph->saddr,sizeof(addr.sin_addr));
        addr.sin_port = tcph->source;
        rule = rule_find_lan(&addr, IPPROTO_TCP);
        if(rule != NULL){
            memcpy(&iph->saddr,&rule->wan.sin_addr,sizeof(rule->wan.sin_addr));
            tcph->source = rule->wan.sin_port;
        }
    }else if(iph->protocol == IPPROTO_UDP){
        struct udphdr* udph = (void*) iph + iph->ihl * 4;
        struct nat_rule* rule;
        memcpy(&addr.sin_addr,&iph->saddr,sizeof(addr.sin_addr));
        addr.sin_port = udph->source;
        rule = rule_find_lan(&addr, IPPROTO_UDP);
        if(rule != NULL){
            memcpy(&iph->saddr,&rule->wan.sin_addr,sizeof(rule->wan.sin_addr));
            udph->source = rule->wan.sin_port;
        }
    }
}

static struct nat_rule* rule_find_wan(struct sockaddr_in *wan, int protocol){
    struct nat_rule *current_rule;
    spin_lock_bh(&nat_spin);
    list_for_each_entry(current_rule, &nat, list_node) {
        if (protocol_match(protocol,current_rule) && sockaddr_in_cmp(wan,&current_rule->wan) == 0) {
            spin_unlock_bh(&nat_spin);
            return current_rule;
        }
    }
    spin_unlock_bh(&nat_spin);
    return NULL;
}

// 外网到内网，改源地址
void nat_wan2lan(struct sk_buff *skb){
    struct iphdr *iph;
    struct sockaddr_in addr = {.sin_family=AF_INET};
    if(!skb)
        return;
    iph = ip_hdr(skb);
    if(iph->protocol == IPPROTO_TCP){
        struct tcphdr* tcph = (void*) iph + iph->ihl * 4; //查找TCP头;
        struct nat_rule* rule;
        memcpy(&addr.sin_addr,&iph->daddr,sizeof(addr.sin_addr));
        addr.sin_port = tcph->dest;
        rule = rule_find_wan(&addr, IPPROTO_TCP);
        if(rule != NULL){
            memcpy(&iph->daddr,&rule->lan.sin_addr,sizeof(rule->lan.sin_addr));
            tcph->dest = rule->lan.sin_port;
        }
    }else if(iph->protocol == IPPROTO_UDP){
        struct udphdr* udph = (void*) iph + iph->ihl * 4;
        struct nat_rule* rule;
        memcpy(&addr.sin_addr,&iph->daddr,sizeof(addr.sin_addr));
        addr.sin_port = udph->dest;
        rule = rule_find_wan(&addr, IPPROTO_UDP);
        if(rule != NULL){
            memcpy(&iph->daddr,&rule->lan.sin_addr,sizeof(rule->lan.sin_addr));
            udph->dest = rule->lan.sin_port;
        }
    }
}

static inline void print_rule(const char* msg, struct nat_rule* target){
    RULE_LOG("%s %pI4:%hu %pI4:%hu %s %s",
             msg, &target->lan.sin_addr,target->lan.sin_port,
             &target->wan.sin_addr,target->wan.sin_port,
             target->flag.tcp ? "TCP" : "",
             target->flag.udp ? "UDP" : ""
    );
}

static int modify_nat(const char* buf,struct nat_rule* target){
    u32 lan_ip,wan_ip;
    u16 lan_port,wan_port;
    u8 flag;
    if(sscanf(buf, "%*x %*d %x %x %hx %hx %hhx",
              &lan_ip, &wan_ip, &lan_port, &wan_port, &flag) < 7){
        return -EIO;
    }
    target->lan.sin_addr.s_addr = htonl(lan_ip);
    target->wan.sin_addr.s_addr = htonl(wan_ip);
    target->lan.sin_port = htons(lan_port);
    target->wan.sin_port = htons(wan_port);
    target->flag.value = flag;
    return 0;
}

static int add_nat(const char* buf, struct nat_rule* target){
    struct nat_rule* new_rule = kzalloc(sizeof(struct nat_rule),GFP_ATOMIC);
    int ret;
    ret = modify_nat(buf,new_rule);
    if(ret != 0) return ret;
    list_add(&new_rule->list_node,&target->list_node);
    print_rule("ADD NAT",new_rule);
    return 0;
}

static inline void del_nat(struct nat_rule* target){
    print_rule("DELETE NAT",target);
    list_del(&target->list_node);
    kfree(target);
}

// 操作对象默认为链表头（第一条规则）
int update_nat(const char *buf) {
    u8 operation;
    short target;
    struct nat_rule* target_rule;
    int ret = -EFAULT;
    spin_lock_bh(&nat_spin);
    sscanf(buf,"%hhx %hd",&operation,&target);
    list_for_each_entry(target_rule, &nat, list_node){
        if(target-- <= 1)
            break;
    }
    switch(operation){
        case 0:
            ret = add_nat(buf,target_rule); break;
        case 1:
            if(list_is_head(&target_rule->list_node,&nat)) break;
            del_nat(target_rule); break;
        case 2:
            if(list_is_head(&target_rule->list_node,&nat)) break;
            print_rule("MODIFY NAT FROM",target_rule);
            ret = modify_nat(buf,target_rule);
            print_rule("MODIFY NAT TO",target_rule);
            break;
        default:;
    }
    spin_unlock_bh(&nat_spin);
    return ret;
}

static int nat_rule_cnt;

static void* nat_seq_start(struct seq_file *m, loff_t *pos){
    spin_lock_bh(&nat_spin);
    nat_rule_cnt = 1;
    return seq_list_start(&nat,*pos);
}

static void* nat_seq_next(struct seq_file *m, void *v,loff_t *pos){
    return seq_list_next(v,&nat,pos);
}

static void nat_seq_stop(struct seq_file *m,void *v){
    spin_unlock_bh(&nat_spin);
}

static int nat_seq_show(struct seq_file *m, void *v){
    struct nat_rule *current_rule = (struct nat_rule *)v;
    seq_printf(m, "%d %pI4:%hu %pI4:%hu %s %s",
               nat_rule_cnt, &current_rule->lan.sin_addr, current_rule->lan.sin_port,
               &current_rule->wan.sin_addr, current_rule->wan.sin_port,
               current_rule->flag.tcp ? "TCP" : "",
               current_rule->flag.udp ? "UDP" : "");
    return 0;
}

static const struct seq_operations rule_seq_ops = {
        .start = nat_seq_start,
        .next = nat_seq_next,
        .stop = nat_seq_stop,
        .show = nat_seq_show,
};

int seq_open_nat(struct inode *inode, struct file *file){
    return seq_open(file,&rule_seq_ops);
}