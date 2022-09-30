//
// Created by csepsk on 2022/8/30.
//

#ifndef KERNEL_FIREWALL_NETHOOKS_H
#define KERNEL_FIREWALL_NETHOOKS_H

#include "tcp_hook.h"
#include "udp_hook.h"
#include "icmp_hook.h"
#include "proc.h"
#include "filter.h"
#include "nat.h"

int register_net_hooks(void);
int unregister_net_hooks(void);

#endif //KERNEL_FIREWALL_NETHOOKS_H
