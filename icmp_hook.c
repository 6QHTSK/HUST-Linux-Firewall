//
// Created by csepsk on 2022/9/2.
//

#include "icmp_hook.h"

static const u64 icmp_timeout = 10 * NSEC_PER_SEC;

enum icmp_package {
    PING_REQUEST = 0,
    PING_REPLY = 1,
    SOURCE_QUENCH = 2,
    ICMP_BLOCK = -1
};

static inline const char* icmp_status_str(enum icmp_package status){
    switch(status){
        case PING_REPLY: return "ICMP REPLY";
        case PING_REQUEST: return "ICMP REQUEST";
        case SOURCE_QUENCH: return "ICMP SOURCE";
        default: return "";
    }
}

struct icmp_status{
    struct rb_node node;
    struct in_addr src_addr, dest_addr; // 源地址 目的地址
    int status;
    u64 timestamp;
};

static DEFINE_SPINLOCK(icmp_map_spin);
static struct rb_root icmp_map = RB_ROOT;

// 由于只有PING_REPLY/PING_REQUEST可以调用此函数，故字段固定为PING_REQUEST/PING_REPLY
static inline void icmp_status_peer(struct icmp_status* dest, const struct icmp_status* src){
    memcpy(&dest->src_addr,&src->dest_addr,sizeof(struct in_addr));
    memcpy(&dest->dest_addr,&src->src_addr,sizeof(struct in_addr));
    dest->timestamp = src->timestamp;
    dest->status = src->status == PING_REPLY ? PING_REQUEST : PING_REPLY;
}

static int icmp_status_cmp(const struct icmp_status* a, const struct icmp_status* b){
    int src_cmp;
    src_cmp = in_addr_cmp(&a->src_addr,&b->src_addr);
    if(src_cmp == 0){
        int dest_cmp;
        dest_cmp = in_addr_cmp(&a->dest_addr,&b->dest_addr);
        if(dest_cmp == 0){
            return a->status == b->status ? 0 : (a->status < b->status ? -1 : 1) ;
        }
        return dest_cmp;
    }
    return src_cmp;
}

static int rb_node_cmp(struct rb_node *rb_node_a, const struct rb_node *rb_node_b){
    struct icmp_status *a = rb_entry(rb_node_a,struct icmp_status ,node);
    struct icmp_status *b = rb_entry(rb_node_b,struct icmp_status ,node);
    return icmp_status_cmp(a,b);
}

static int icmp_rb_node_cmp(const void *void_a, const struct rb_node *rb_node_b){
    struct icmp_status *a = (struct icmp_status*) void_a;
    struct icmp_status *b = rb_entry(rb_node_b,struct icmp_status ,node);
    return icmp_status_cmp(a,b);
}

static inline struct icmp_status * icmp_map_find(const struct icmp_status *target){
    return rb_entry_safe(rb_find(target,&icmp_map,icmp_rb_node_cmp),struct icmp_status,node);
}

static struct icmp_status * icmp_map_find_peer(const struct icmp_status *status){
    struct icmp_status status_peer;
    icmp_status_peer(&status_peer,status);
    return icmp_map_find(&status_peer);
}

static bool icmp_map_insert(const struct icmp_status *data){
    struct icmp_status *insert_node = kmalloc(sizeof(struct icmp_status),GFP_ATOMIC);
    memcpy(insert_node,data,sizeof(struct icmp_status));
    if(rb_find_add(&insert_node->node,&icmp_map, rb_node_cmp) != NULL){
        kfree(insert_node);
        return false;
    }
    return true;
}

//unsafe!
static inline void icmp_map_delete(struct icmp_status *data){
    rb_erase(&data->node,&icmp_map);
    kfree(data);
}

static inline void print_icmp_status(const char* msg, const struct icmp_status* status){
    CONNECTION_LOG("%s %pI4 <=> %pI4",msg, &status->src_addr, &status->dest_addr);
}

static void icmp_map_delete_expired(void){
    struct rb_node *node;
    u64 current_time = ktime_get_boottime_ns();
    again:
    for(node = rb_first(&icmp_map); node != NULL; node = rb_next(node)){
        struct icmp_status* current_status = rb_entry(node,struct icmp_status,node);
        if(current_time >= current_status->timestamp + icmp_timeout){
            struct icmp_status *current_status_peer =  icmp_map_find_peer(current_status);
            print_icmp_status("ICMP CONNECTION Expired", current_status);
            icmp_map_delete(current_status);
            icmp_map_delete(current_status_peer);
            goto again;
        }
    }
}

static inline int convert_icmp_status(struct icmphdr *icmph){
    int ret = ICMP_BLOCK;
    switch(icmph->type){
        case 0: ret = PING_REPLY; break;
        case 3: ret = icmph->code <= 5 ?  PING_REQUEST : ICMP_BLOCK; break;
        case 4: ret = SOURCE_QUENCH; break;
        case 8: ret = PING_REQUEST; break;
        case 11:ret = icmph->code == 0 ?  PING_REQUEST : ICMP_BLOCK; break;
    }
    return ret;
}

inline void register_net_hook_icmp_hook(void){}

// 1 pass 0 deny
int check_icmp_packet(struct sk_buff *skb){
    struct icmphdr *icmph = NULL;
    struct iphdr *iph;
    if(!skb)
        return 1;
    iph = ip_hdr(skb);
    icmph = (void*) iph + iph->ihl * 4;
    if(iph->protocol == IPPROTO_ICMP){
        // 构造icmp Status
        struct icmp_status target = {
                .src_addr = {iph->saddr},
                .dest_addr = {iph->daddr},
                .status = convert_icmp_status(icmph)
        };
        struct icmp_status *p_status,*p_status_peer;
        if(target.status == ICMP_BLOCK){
            return 0;
        }
        // 查哈希表
        spin_lock_bh(&icmp_map_spin);
        icmp_map_delete_expired();
        p_status = icmp_map_find(&target);
        if(p_status == NULL){
            // 在红黑树未查询到目标，认为是新连接
            if(target.status == PING_REQUEST){
                p_status_peer = kzalloc(sizeof(struct icmp_status), GFP_ATOMIC);
                p_status = kzalloc(sizeof(struct icmp_status), GFP_ATOMIC);
                memcpy(p_status,&target,sizeof(struct icmp_status));
                p_status->timestamp = ktime_get_boottime_ns();
                icmp_status_peer(p_status_peer, p_status);

                if(rule_matching(&p_status->src_addr,&p_status->dest_addr,IPPROTO_ICMP,0,0) == 0){
                    goto deny;
                }

//                print_icmp_status("Accept new icmp connection",p_status);
//                print_icmp_status("Accept new icmp connection",p_status_peer);
                icmp_map_insert(p_status);
                // 加入反向规则
                icmp_map_insert(p_status_peer);
                goto access;
            }else if(target.status == SOURCE_QUENCH){
                goto access;
            }else{
                goto deny;
            }
        }else{
            // 在红黑树查询到目标，检查是否超时
            p_status_peer = icmp_map_find_peer(&target);
            //print_icmp_status(&target);
            p_status_peer->timestamp = p_status->timestamp = ktime_get_boottime_ns();
            goto access;
        }
        access:
        spin_unlock_bh(&icmp_map_spin); return 1;
        deny:
        spin_unlock_bh(&icmp_map_spin); return 0;
    }
    return 0; // 其余协议一律放通
}

inline void unregister_net_hook_icmp_hook(void){}

// void* = rb_node*
static void* connection_seq_start(struct seq_file *m, loff_t *pos){
    struct rb_node *node;
    loff_t index = *pos;
    spin_lock_bh(&icmp_map_spin);
    icmp_map_delete_expired();
    node = rb_first(&icmp_map);
    while(index-- > 0 && node != NULL){
        node = rb_next(node);
    }
    return node;
}

static void* connection_seq_next(struct seq_file *m, void *v, loff_t *pos){
    ++*pos;
    return rb_next((struct rb_node*)v);
}

static void connection_seq_stop(struct seq_file *m, void *v){
    spin_unlock_bh(&icmp_map_spin);
}

static int connection_seq_show(struct seq_file *m, void *v){
    struct icmp_status *status = rb_entry_safe((struct rb_node *)v,struct icmp_status,node);
    if(status != NULL){
        u64 interval = ktime_get_boottime_ns() - status->timestamp;
        seq_printf(m, "%s %pI4 => %pI4 %5llu.%03llu seconds ago\n",
                   icmp_status_str(status->status),
                   &status->src_addr, &status->dest_addr,
                   interval / NSEC_PER_SEC,interval % NSEC_PER_SEC / NSEC_PER_MSEC);
    }
    return 0;
}

static const struct seq_operations seq_connection = {
        .start = connection_seq_start,
        .next = connection_seq_next,
        .stop = connection_seq_stop,
        .show = connection_seq_show,
};

int seq_open_icmp_connection(struct inode *inode, struct file *file){
    return seq_open(file,&seq_connection);
}
