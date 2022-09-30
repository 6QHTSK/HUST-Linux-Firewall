//
// Created by csepsk on 2022/8/30.
//

#include "nethooks.h"

// 宏钩子
static u32 pre_routing_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    nat_wan2lan(skb);
    return NF_ACCEPT;
}
static u32 local_in_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    if(check_tcp_packet(skb) || check_udp_packet(skb) || check_icmp_packet(skb))
        return NF_ACCEPT;
    else
        return NF_DROP;
}
static u32 forward_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    if(check_tcp_packet(skb) || check_udp_packet(skb) || check_icmp_packet(skb))
        return NF_ACCEPT;
    else
        return NF_DROP;
}
static u32 local_out_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    if(check_tcp_packet(skb) || check_udp_packet(skb) || check_icmp_packet(skb))
        return NF_ACCEPT;
    else
        return NF_DROP;
}
static u32 post_routing_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    nat_lan2wan(skb);
    return NF_ACCEPT;
}

static struct nf_hook_ops nfho_hook_pre_routing,nfho_hook_local_in,nfho_hook_forward,nfho_hook_local_out,nfho_hook_post_routing;

static inline void register_hook(struct nf_hook_ops* nfho_hook,nf_hookfn hook, unsigned int hooknum){
    nfho_hook->hook = hook;
    nfho_hook->pf = PF_INET;
    nfho_hook->hooknum = hooknum;
    nfho_hook->priority = NF_IP_PRI_FILTER;
    nf_register_net_hook(&init_net,nfho_hook);
}

static inline void unregister_hook(struct nf_hook_ops* nfho_hook){
    nf_unregister_net_hook(&init_net,nfho_hook);
}

int register_net_hooks(void){
    register_hook(&nfho_hook_pre_routing,pre_routing_hook,NF_INET_PRE_ROUTING);
    register_hook(&nfho_hook_local_in,local_in_hook,NF_INET_LOCAL_IN);
    register_hook(&nfho_hook_forward,forward_hook,NF_INET_FORWARD);
    register_hook(&nfho_hook_local_out,local_out_hook,NF_INET_LOCAL_OUT);
    register_hook(&nfho_hook_post_routing,post_routing_hook,NF_INET_POST_ROUTING);
    register_net_hook_tcp_hook();
    register_net_hook_udp_hook();
    register_net_hook_icmp_hook();
    register_filter();
    register_proc_file();
    return 0;
}

int unregister_net_hooks(void){
    unregister_hook(&nfho_hook_pre_routing);
    unregister_hook(&nfho_hook_local_in);
    unregister_hook(&nfho_hook_forward);
    unregister_hook(&nfho_hook_local_out);
    unregister_hook(&nfho_hook_post_routing);
    unregister_net_hook_tcp_hook();
    unregister_net_hook_udp_hook();
    unregister_net_hook_icmp_hook();
    unregister_proc_file();
    return 0;
}
