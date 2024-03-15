#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#define MAX_PAYLOAD_SIZE 128

struct payload_event
{
    __u32 cpu;
    __u32 payload_len;
    char payload[MAX_PAYLOAD_SIZE];
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct payload_event));
    __uint(max_entries, 256);
} events_map SEC(".maps");

SEC("xdp_packet")
int xdp_capture_payload(struct xdp_md *ctx)
{
    struct payload_event event = {};
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    event.cpu = bpf_get_smp_processor_id();

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
        return XDP_PASS;

    __u32 payload_len = data_end - (void *)tcp - tcp->doff * 4;
    if (payload_len > MAX_PAYLOAD_SIZE)
        payload_len = MAX_PAYLOAD_SIZE;

    event.payload_len = payload_len;
    __builtin_memcpy(event.payload, (void *)tcp + tcp->doff * 4, payload_len);

    bpf_perf_event_output(ctx, &events_map, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";