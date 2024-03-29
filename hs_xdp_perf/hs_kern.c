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
#define MAX_PAYLOAD_SIZE 20

struct connection_map
{
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u8 payload[MAX_PAYLOAD_SIZE];
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

struct bpf_elf_map SEC("maps") hs_xdp_payload_map = {
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

// SEC("xdp")
// int hs_xdp_prog(struct xdp_md *ctx)
// {
//     void *data = (void *)(long)ctx->data;
//     void *data_end = (void *)(long)ctx->data_end;
//     struct ethhdr *eth = data;
//     struct iphdr *iph;
//     struct tcphdr *tcph;

//     __u64 ktime;
//     __u64 flags = BPF_F_CURRENT_CPU;

//     int ret;
//     struct connection_map con_map;

//     // if (eth + 1 > data_end)
//     //     return XDP_PASS;

//     if (!eth || (void *)eth + ETH_HLEN > data_end)
//         return XDP_PASS;

//     // IP header validation
//     iph = data + sizeof(*eth);
//     // if (iph + 1 > data_end)
//     //     return XDP_PASS;
//     if (!iph || (void *)iph + sizeof(*iph) > data_end)
//         return XDP_PASS;
//     if (iph->protocol != IPPROTO_TCP)
//         return XDP_PASS;

//     // TCP header validation
//     tcph = (void *)iph + sizeof(*iph);
//     // if (tcph + 1 > data_end)
//     //     return XDP_PASS;
//     if (!tcph || (void *)tcph + sizeof(*tcph) > data_end)
//         return XDP_PASS;

//     __u32 payload_size = data_end - (void *)tcph - sizeof(*tcph);
//     if (payload_size > MAX_PAYLOAD_SIZE)
//     {
//         payload_size = MAX_PAYLOAD_SIZE;
//     }

//     void *payload_ptr = (void *)tcph + sizeof(*tcph);
//     bpf_probe_read(&con_map.payload, payload_size, payload_ptr);

//     con_map.saddr = iph->daddr;
//     con_map.daddr = iph->saddr;
//     con_map.sport = tcph->dest;
//     con_map.dport = tcph->source;

//     ret = bpf_perf_event_output(ctx, &hs_xdp_payload_map, flags, &con_map, sizeof(con_map));
//     return XDP_PASS;
// }

SEC("xdp")
int hs_xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;

    __u64 ktime;
    __u64 flags = BPF_F_CURRENT_CPU;

    int ret;
    struct connection_map con_map;

    if (!eth || (void *)eth + ETH_HLEN > data_end)
        return XDP_PASS;

    iph = data + sizeof(*eth);
    if (!iph || (void *)iph + sizeof(*iph) > data_end)
        return XDP_PASS;
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    tcph = (void *)iph + sizeof(*iph);
    if (!tcph || (void *)tcph + sizeof(*tcph) > data_end)
        return XDP_PASS;

    __u32 payload_size = data_end - (void *)tcph - sizeof(*tcph);
    if (payload_size > MAX_PAYLOAD_SIZE)
    {
        payload_size = MAX_PAYLOAD_SIZE;
    }

    __u32 offset = sizeof(*eth) + sizeof(*iph) + sizeof(*tcph);

    __u32 pl_size = 20;

    // ret = bpf_xdp_load_bytes(ctx, offset, con_map.payload, pl_size);
    // if (ret < 0)
    //     return XDP_PASS;

    __u32 payload_offset = offset;
    __u32 payload_size_probe = data_end - data - payload_offset;
    if (payload_size_probe > MAX_PAYLOAD_SIZE)
    {
        payload_size_probe = MAX_PAYLOAD_SIZE;
    }

    if (payload_size_probe <= 0)
    {
        payload_size_probe = 1;
    }

    payload_size_probe = MAX_PAYLOAD_SIZE;
    if (payload_size_probe != 1)
        ret = bpf_probe_read_kernel(con_map.payload, (__u32)payload_size_probe, data + payload_offset);
    else
        return XDP_PASS;
    if (ret < 0)
        return XDP_TX;

    con_map.saddr = iph->daddr;
    con_map.daddr = iph->saddr;
    con_map.sport = tcph->dest;
    con_map.dport = tcph->source;

    ret = bpf_perf_event_output(ctx, &hs_xdp_payload_map, flags, &con_map, sizeof(con_map));
    if (ret < 0)
        return XDP_DROP;
    else
        return XDP_TX;
}
char _license[] SEC("license") = "Dual BSD/GPL"; //"GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;