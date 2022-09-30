//
// Created by csepsk on 2022/9/2.
//

#include "udp_hook.h"

static const u64 udp_timeout = 10 * NSEC_PER_SEC;

struct udp_status{
    struct rb_node node;
    struct sockaddr_in src_addr, dest_addr; // 源地址 目的地址
    u64 timestamp;
};

static DEFINE_SPINLOCK(udp_map_spin);
static struct rb_root udp_map = RB_ROOT;

static inline void udp_status_peer(struct udp_status* dest, const struct udp_status* src){
    memcpy(&dest->src_addr,&src->dest_addr,sizeof(struct sockaddr_in));
    memcpy(&dest->dest_addr,&src->src_addr,sizeof(struct sockaddr_in));
    dest->timestamp = src->timestamp;
}

static int udp_status_cmp(const struct udp_status* a, const struct udp_status* b){
    int src_cmp;
    src_cmp = sockaddr_in_cmp(&a->src_addr,&b->src_addr);
    if(src_cmp == 0){
        return sockaddr_in_cmp(&a->dest_addr,&b->dest_addr);
    }
    return src_cmp;
}

static int rb_node_cmp(struct rb_node *rb_node_a, const struct rb_node *rb_node_b){
    struct udp_status *a = rb_entry(rb_node_a,struct udp_status ,node);
    struct udp_status *b = rb_entry(rb_node_b,struct udp_status ,node);
    return udp_status_cmp(a,b);
}

static int udp_rb_node_cmp(const void *void_a, const struct rb_node *rb_node_b){
    struct udp_status *a = (struct udp_status*) void_a;
    struct udp_status *b = rb_entry(rb_node_b,struct udp_status ,node);
    return udp_status_cmp(a,b);
}

static inline struct udp_status * udp_map_find(const struct udp_status *target){
    return rb_entry_safe(rb_find(target,&udp_map,udp_rb_node_cmp),struct udp_status,node);
}

static struct udp_status* udp_map_find_peer(const struct udp_status *status){
    struct udp_status status_peer;
    udp_status_peer(&status_peer, status);
    return udp_map_find(&status_peer);
}

static bool udp_map_insert(const struct udp_status *data){
    struct udp_status *insert_node = kmalloc(sizeof(struct udp_status),GFP_ATOMIC);
    memcpy(insert_node,data,sizeof(struct udp_status));
    if(rb_find_add(&insert_node->node,&udp_map, rb_node_cmp) != NULL){
        kfree(insert_node);
        return false;
    }
    return true;
}

static void inline udp_map_delete(struct udp_status *data){
    rb_erase(&data->node,&udp_map);
    kfree(data);
}

static inline void print_udp_status(const char* msg, const struct udp_status* status){
    CONNECTION_LOG("%s %pISp => %pISp",msg,&status->src_addr,&status->dest_addr);
}

static void udp_map_delete_expired(void){
    struct rb_node *node;
    u64 current_time = ktime_get_boottime_ns();
    again:
    for(node = rb_first(&udp_map); node != NULL; node = rb_next(node)){
        struct udp_status* current_status = rb_entry(node,struct udp_status,node);
        if(current_time >= current_status->timestamp + udp_timeout){
            struct udp_status *current_status_peer =  udp_map_find_peer(current_status);
            print_udp_status("UDP CONNECTION Expired", current_status);
            udp_map_delete(current_status);
            udp_map_delete(current_status_peer);
            goto again;
        }
    }
}

inline void register_net_hook_udp_hook(void){}

// 1 pass 0 deny
int check_udp_packet(struct sk_buff *skb){
    struct udphdr *udph = NULL;
    struct iphdr *iph;
    if(!skb)
        return 1;
    iph = ip_hdr(skb);
    udph = (void*) iph + iph->ihl * 4;
    if(iph->protocol == IPPROTO_UDP){
        // 构造udp Status
        struct udp_status target = {
                .src_addr = {.sin_family=AF_INET, .sin_port=udph->source,.sin_addr= {iph->saddr}},
                .dest_addr = {.sin_family=AF_INET, .sin_port=udph->dest, .sin_addr={iph->daddr}},
        };
        // 查哈希表
        struct udp_status *p_status,*p_status_peer;
        spin_lock_bh(&udp_map_spin);
        udp_map_delete_expired();
        p_status = udp_map_find(&target);
        if(p_status == NULL){
            p_status = kzalloc(sizeof(struct udp_status), GFP_ATOMIC);
            p_status_peer = kzalloc(sizeof(struct udp_status), GFP_ATOMIC);
            memcpy(p_status,&target,sizeof(struct udp_status));
            p_status->timestamp = ktime_get_boottime_ns();
            udp_status_peer(p_status_peer, p_status);

            if(rule_matching(&p_status->src_addr.sin_addr,&p_status->dest_addr.sin_addr,
                             IPPROTO_UDP,p_status->src_addr.sin_port,p_status->dest_addr.sin_port) == 0){
                goto deny;
            }
            if(rule_matching(&p_status_peer->src_addr.sin_addr,&p_status_peer->dest_addr.sin_addr,
                             IPPROTO_UDP,p_status_peer->src_addr.sin_port,p_status_peer->dest_addr.sin_port) == 0){
                goto deny;
            }

//            print_udp_status("Accept new udp connection", p_status);
//            print_udp_status("Accept new udp connection", p_status_peer);
            udp_map_insert(p_status);
            // 加入反向规则
            udp_map_insert(p_status_peer);
            goto access;
        }else{
            // 在红黑树查询到目标
            p_status_peer = udp_map_find_peer(&target);
            //print_udp_status(&target);
            p_status_peer->timestamp = p_status->timestamp = ktime_get_boottime_ns();
            goto access;
        }
        access:
        spin_unlock_bh(&udp_map_spin); return 1;
        deny:
        spin_unlock_bh(&udp_map_spin); return 0;
    }
    return 0;
}

void inline unregister_net_hook_udp_hook(void){}

// void* = rb_node*
static void* connection_seq_start(struct seq_file *m, loff_t *pos){
    struct rb_node *node;
    loff_t index = *pos;
    spin_lock_bh(&udp_map_spin);
    udp_map_delete_expired();
    node = rb_first(&udp_map);
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
    spin_unlock_bh(&udp_map_spin);
}

static int connection_seq_show(struct seq_file *m, void *v){
    struct udp_status *status = rb_entry_safe((struct rb_node *)v,struct udp_status,node);
    if(status != NULL){
        u64 interval = ktime_get_boottime_ns() - status->timestamp;
        seq_printf(m, "%pISp => %pISp %5llu.%03llu seconds ago\n",
                   &status->src_addr,
                   &status->dest_addr,
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

int seq_open_udp_connection(struct inode *inode, struct file *file){
    return seq_open(file,&seq_connection);
}
