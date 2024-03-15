/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */

/* Copyright (C) 2021 Authors of Cilium */

// #include <bpf/api.h>

#include "linux/if_ether.h"

#include "linux/ip.h"

#include "linux/tcp.h"

#include "linux/bpf.h"

#include <bpf/bpf_helpers.h>

#include <linux/version.h>

#include <linux/ptrace.h>

#include <linux/in.h>

#include <linux/pkt_cls.h>

struct connection_info
{

    __be32 daddr;

    __be32 saddr;

    __be16 sport;

    __be16 dport;

    __be32 seq_no;

    __u64 pktcnt;

    __u64 cur_ktime;

} __packed;

struct connection_map
{

    __be32 daddr;

    __be32 saddr;

    __be16 sport;

    __be16 dport;

} __packed;

struct rtt_keys
{

    char key_name[32];

} __packed;

#define MAX_CPUS 128

#define PIN_GLOBAL_NS 2

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

struct bpf_elf_map SEC("maps") lb_map_ack = {

    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,

    .size_key = sizeof(int),

    .size_value = sizeof(u32),

    .max_elem = MAX_CPUS,

    .pinning = PIN_GLOBAL_NS,

};

struct bpf_map_def SEC("maps") count_delay = {

    .type = BPF_MAP_TYPE_LRU_HASH,

    .key_size = sizeof(struct connection_map),

    .value_size = sizeof(__u32),

    .max_entries = 1024,

};

struct bpf_elf_map SEC("maps") rtt_config = {

    .type = BPF_MAP_TYPE_LRU_HASH,

    .size_key = sizeof(struct rtt_keys),

    .size_value = sizeof(__u32),

    .max_elem = 5,

    .pinning = PIN_GLOBAL_NS,

};

SEC("tc_pass_lb")

int tc_pass_lb_prog(struct __sk_buff *ctx)

{

    __u64 ktime;

    __u32 *delaycount, delayindex = 0, *value;

    struct connection_info connection;

    struct connection_map con_map;

    struct ethhdr *eth = NULL;

    struct iphdr *iph = NULL;

    struct tcphdr *tcph = NULL;

    void *data = (void *)(long)ctx->data;

    void *data_end = (void *)(long)ctx->data_end;

    u64 flags = BPF_F_CURRENT_CPU;

    int ret;

    int fd;

    struct rtt_keys rtt_key, *key = &rtt_key;

    if (!data || !data_end)

        return TC_ACT_OK;

    eth = (struct ethhdr *)data;

    if (!eth || eth + 1 > data_end)

        return TC_ACT_OK;

    if (data + ETH_HLEN > data_end)

        return TC_ACT_OK;

    if (eth->h_proto != htons(ETH_P_IP))

        return TC_ACT_OK;

    iph = (void *)eth + ETH_HLEN;

    if (!iph || iph + 1 > data_end)

        return TC_ACT_OK;

    if (iph->protocol != IPPROTO_TCP)

        return TC_ACT_OK;

    tcph = (void *)iph + sizeof(*iph);

    if (!tcph || tcph + 1 > data_end)

        return TC_ACT_OK;

    memset(key->key_name, 0, sizeof(key->key_name));

    strncpy(key->key_name, "port", strlen("port") + 1);

    key->key_name[strlen("port")] = 0;

    value = bpf_map_lookup_elem(&rtt_config, &rtt_key);

    if (!value)

        return TC_ACT_OK;

    if ((tcph->source != htons(*value)))

        return TC_ACT_OK;

    ktime = bpf_ktime_get_ns();

    connection.daddr = iph->daddr;

    connection.saddr = iph->saddr;

    connection.sport = tcph->source;

    connection.dport = tcph->dest;

    connection.cur_ktime = ktime;

    connection.seq_no = tcph->ack_seq;

    con_map.daddr = iph->daddr;

    con_map.saddr = iph->saddr;

    con_map.sport = tcph->source;

    con_map.dport = tcph->dest;

    delaycount = bpf_map_lookup_elem(&count_delay, &con_map);

    if (delaycount)

        delayindex = *delaycount;

    connection.pktcnt = delayindex;

    delayindex++;

    ret = bpf_perf_event_output(ctx, &lb_map_ack, flags, &connection, sizeof(connection));

    if (ret)

        bpf_printk("perf_event_output failed: %d\n", ret);

    bpf_map_update_elem(&count_delay, &con_map, &delayindex, BPF_ANY);

    return TC_ACT_OK;
}

// a) memset and memcpy beyond a size will invoke builtin functions which is not supported - compilation and runtime {error invalid indirect read from stack off -104+0 size 80}. size represents actual size of the structure without padding and if we try to read beyond the actual size into pad same error is thrown - https://docs.cilium.io/en/v1.7/bpf/

// b) loop has to be static otherwise not supported

// c) adding dynamic value to a pointer messes with the range. further access to location in valid range also will fail.

// d) check for null pointers else {invalid mem access 'inv'} or for maps {R0 invalid mem access 'map_value_or_null'} - https://www.kernel.org/doc/html/latest/bpf/verifier.html

char _license[] SEC("license") = "GPL";

u32 _version SEC("version") = LINUX_VERSION_CODE;