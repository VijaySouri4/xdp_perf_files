/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (C) 2021 Authors of Cilium */
// #include <bpf/api.h>

#include "linux/if_ether.h"
#include "linux/ip.h"
#include "linux/tcp.h"
#include "linux/bpf.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_tracing.h"
#include <linux/version.h>
#include <linux/ptrace.h>
#include <linux/in.h>
#include <linux/types.h>
#include "linux/pkt_cls.h"
#include <stdbool.h>
#define NANO_TO_MICRO 1000
#define PIN_GLOBAL_NS 2

struct connection_map
{
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
} __attribute__((packed));

struct bpf_elf_map
{
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
};

struct bpf_elf_map SEC("maps") adjust_cpu = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .size_key = sizeof(int),
    .size_value = sizeof(__u32),
    .max_elem = 20,
    .pinning = PIN_GLOBAL_NS,
};

/*
 * struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, pid_t);
} my_pid_map SEC(".maps");
 * LIBBPF_PIN_BY_NAME
 * PIN_GLOBAL_NS
 * */

SEC("tc_lb_ingress")
int tc_lb_ingress_prog(struct __sk_buff *ctx)
{
    __u64 ktime;
    struct ethhdr *eth = NULL;
    struct iphdr *iph = NULL;
    struct tcphdr *tcph = NULL;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 flags = BPF_F_CURRENT_CPU;
    int ret;
    struct connection_map con_map;
    if (!data || !data_end)
        return TC_ACT_OK;
    eth = (struct ethhdr *)data;
    if (!eth || (void *)eth + ETH_HLEN > data_end)
        return TC_ACT_OK;
    if (data + ETH_HLEN > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    iph = (void *)eth + ETH_HLEN;
    if (!iph || (void *)iph + sizeof(*iph) > data_end)
        return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    tcph = (void *)iph + sizeof(*iph);
    if (!tcph || (void *)tcph + sizeof(*tcph) > data_end)
        return TC_ACT_OK;
    // if ((tcph->dest != bpf_htons(9090)))
    //         return TC_ACT_OK;
    con_map.saddr = iph->daddr;
    con_map.daddr = iph->saddr;
    con_map.sport = tcph->dest;
    con_map.dport = tcph->source;
    ret = bpf_perf_event_output(ctx, &adjust_cpu, flags, &con_map, sizeof(con_map));
    return TC_ACT_OK;
}
char _license[] SEC("license") = "Dual BSD/GPL"; //"GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;
