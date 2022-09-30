//
// Created by csepsk on 2022/9/27.
//

#ifndef KERNEL_FIREWALL_UTILS_H
#define KERNEL_FIREWALL_UTILS_H

#include <linux/in.h>

static int inline port_cmp(const __be16 a, const __be16 b){
    return ntohs(a) == ntohs(b) ? 0 : (ntohs(a) < ntohs(b) ? -1 : 1);
}

static int inline in_addr_cmp(const struct in_addr* a, const struct in_addr* b){
    return ntohl(a->s_addr) == ntohl(b->s_addr) ? 0 : (ntohl(a->s_addr) < ntohl(b->s_addr) ? -1 : 1);
}

static int inline sockaddr_in_cmp(const struct sockaddr_in* a, const struct sockaddr_in* b){
    return in_addr_cmp(&a->sin_addr,&b->sin_addr) == 0 ? port_cmp(a->sin_port,b->sin_port) : in_addr_cmp(&a->sin_addr,&b->sin_addr);
}

#endif //KERNEL_FIREWALL_UTILS_H
