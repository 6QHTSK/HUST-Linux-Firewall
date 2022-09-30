//
// Created by csepsk on 2022/8/30.
//

#include "tcp_hook.h"

static const u64 tcp_timeout = 60 * NSEC_PER_SEC;

struct tcp_status {
    struct rb_node node;
    struct sockaddr_in src_addr,dest_addr; // 源地址 目的地址
    u64 timestamp;
    union{
        struct{
            u8 syn:1;
            u8 syn_peer:1;
            u8 fin:1;
            u8 fin_peer:1;
        };
        u8 value;
    }flag;
};

const char* convert_flag_status(struct tcp_status* status){
    if(status->flag.value < 0x3){
        return "SYNC";
    }else if(status->flag.value == 0x3){
        return "ESTAB";
    }else{
        return "FIN";
    }
}

static DEFINE_SPINLOCK(tcp_map_spin);
static struct rb_root tcp_map = RB_ROOT;

static inline void tcp_status_peer(struct tcp_status* dest, const struct tcp_status* src){
    memcpy(&dest->src_addr,&src->dest_addr,sizeof(struct sockaddr_in));
    memcpy(&dest->dest_addr,&src->src_addr,sizeof(struct sockaddr_in));
    dest->timestamp = src->timestamp;
    dest->flag.value = ((src->flag.value & 0x5) << 1) | ((src->flag.value & 0xA) >> 1);
}

static int tcp_status_cmp(struct tcp_status *a, struct tcp_status *b){
    int src_cmp;
    src_cmp = sockaddr_in_cmp(&a->src_addr,&b->src_addr);
    if(src_cmp == 0){
        return sockaddr_in_cmp(&a->dest_addr,&b->dest_addr);
    }
    return src_cmp;
}

static int rb_node_cmp(struct rb_node *rb_node_a, const struct rb_node *rb_node_b){
    struct tcp_status *a = rb_entry(rb_node_a, struct tcp_status , node);
    struct tcp_status *b = rb_entry(rb_node_b, struct tcp_status , node);
    return tcp_status_cmp(a,b);
}

static int tcp_rb_node_cmp(const void *void_a, const struct rb_node *rb_node_b){
    struct tcp_status *a = (struct tcp_status*) void_a;
    struct tcp_status *b = rb_entry(rb_node_b, struct tcp_status , node);
    return tcp_status_cmp(a,b);
}

static inline struct tcp_status* tcp_map_find(const struct tcp_status *target){
    return rb_entry_safe(rb_find(target, &tcp_map, tcp_rb_node_cmp), struct tcp_status, node);
}

static struct tcp_status *tcp_map_find_peer(const struct tcp_status *status){
    struct tcp_status status_peer;
    tcp_status_peer(&status_peer, status);
    return tcp_map_find(&status_peer);
}

static bool tcp_map_insert(const struct tcp_status *data){
    struct tcp_status *insert_node = kmalloc(sizeof(struct tcp_status), GFP_ATOMIC);
    memcpy(insert_node,data,sizeof(struct tcp_status));
    if(rb_find_add(&insert_node->node, &tcp_map, rb_node_cmp) != NULL){
        kfree(insert_node);
        return false;
    }
    return true;
}

//unsafe!
static inline void tcp_map_delete(struct tcp_status *data){
        rb_erase(&data->node,&tcp_map);
        kfree(data);
}

static inline void print_tcp_status(const char* msg, const struct tcp_status* status){
    CONNECTION_LOG("%s %pISp <=> %pISp", msg, &status->src_addr, &status->dest_addr);
}

// 遍历红黑树采用中序遍历，其遍历顺序与节点顺序相关，故中途删除后续的节点不会影响中序遍历的顺序
static void tcp_map_delete_expired(void){
    struct rb_node *node;
    u64 current_time = ktime_get_boottime_ns();
    again:
    for(node = rb_first(&tcp_map); node != NULL; node = rb_next(node)){
        struct tcp_status* current_status = rb_entry(node, struct tcp_status, node);
        if(current_time >= current_status->timestamp + tcp_timeout){
            struct tcp_status *current_status_peer =  tcp_map_find_peer(current_status);
            print_tcp_status("TCP CONNECTION Expired",current_status);
            tcp_map_delete(current_status);
            tcp_map_delete(current_status_peer);
            goto again;
        }
    }
}

inline void register_net_hook_tcp_hook(void){}

// 1 pass 0 deny
int check_tcp_packet(struct sk_buff *skb){
    struct tcphdr *tcph = NULL;
    struct iphdr *iph;
    if(!skb)
        return 0;
    iph = ip_hdr(skb);
    tcph = (void*) iph + iph->ihl * 4; //查找TCP头;
    if(iph->protocol == IPPROTO_TCP){
        // 构造TCP Status
        struct tcp_status target = {
                .src_addr = {.sin_family=AF_INET, .sin_port=tcph->source,.sin_addr= {iph->saddr}},
                .dest_addr = {.sin_family=AF_INET, .sin_port=tcph->dest, .sin_addr={iph->daddr}},
        };
        // 查哈希表
        struct tcp_status *p_status, *p_status_peer;
        spin_lock_bh(&tcp_map_spin);
        tcp_map_delete_expired();
        p_status = tcp_map_find(&target);
        if(p_status == NULL){
            // 在红黑树未查询到目标，认为是新连接
            if(tcph->syn){
                p_status = kzalloc(sizeof(struct tcp_status), GFP_ATOMIC);
                p_status_peer = kzalloc(sizeof(struct tcp_status), GFP_ATOMIC);
                memcpy(p_status,&target,sizeof(struct tcp_status));
                p_status->timestamp = ktime_get_boottime_ns();
                p_status->flag.syn = 1;
                tcp_status_peer(p_status_peer, p_status);

                if(rule_matching(&p_status->src_addr.sin_addr,&p_status->dest_addr.sin_addr,
                              IPPROTO_TCP,p_status->src_addr.sin_port,p_status->dest_addr.sin_port) == 0){
                    goto deny;
                }
                if(rule_matching(&p_status_peer->src_addr.sin_addr,&p_status_peer->dest_addr.sin_addr,
                                 IPPROTO_TCP,p_status_peer->src_addr.sin_port,p_status_peer->dest_addr.sin_port) == 0){
                    goto deny;
                }

//                print_tcp_status("Accept new tcp connection:",p_status);
//                print_tcp_status("Accept new tcp connection:",p_status_peer);
                tcp_map_insert(p_status);
                // 加入反向规则
                tcp_map_insert(p_status_peer);
                goto access;
            }else{
                goto deny;
            }
        }else{
            // 正常连接以及最终四次挥手过程中，不可能会出现没有ack和有syn的报文。
            if(p_status->flag.value >= 0x3 && (!tcph->ack || tcph->syn)){
                goto deny;
            }
            // 在红黑树查询到目标
            p_status_peer = tcp_map_find_peer(&target);
            //print_tcp_status(&target);
            p_status_peer->timestamp = p_status->timestamp = ktime_get_boottime_ns();
            if(tcph->fin){
                p_status->flag.fin = 1;
                p_status_peer->flag.fin_peer = 1;
                //printk("Received FIN ");
                //print_tcp_status(&target);
            }else if(tcph->rst){
                print_tcp_status("TCP Connection RST",p_status);
                tcp_map_delete(p_status);
                tcp_map_delete(p_status_peer);
            }else if(tcph->ack && p_status->flag.value == 0xF){
                print_tcp_status("TCP Connection Closed",p_status);
                tcp_map_delete(p_status);
                tcp_map_delete(p_status_peer);
            }
            goto access;
        }
        access:
        spin_unlock_bh(&tcp_map_spin); return 1;
        deny:
        spin_unlock_bh(&tcp_map_spin); return 0;
    }
    return 0;
}

void inline unregister_net_hook_tcp_hook(void){}

// void* = rb_node*
static void* connection_seq_start(struct seq_file *m, loff_t *pos){
    struct rb_node *node;
    loff_t index = *pos;
    spin_lock_bh(&tcp_map_spin);
    tcp_map_delete_expired();
    node = rb_first(&tcp_map);
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
    spin_unlock_bh(&tcp_map_spin);
}

static int connection_seq_show(struct seq_file *m, void *v){
    struct tcp_status *status = rb_entry_safe((struct rb_node *)v, struct tcp_status, node);
    if(status != NULL){
        u64 interval = ktime_get_boottime_ns() - status->timestamp;
        seq_printf(m, "%pISp => %pISp #%s %5llu.%03llu seconds ago\n",
                   &status->src_addr,
                   &status->dest_addr,
                   convert_flag_status(status),
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

int seq_open_tcp_connection(struct inode *inode, struct file *file){
    return seq_open(file,&seq_connection);
}
