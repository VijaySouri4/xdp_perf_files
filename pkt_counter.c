#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_counter SEC(".maps");

SEC("socket")
int count_packets(struct __sk_buff *skb)
{
    __u32 key = 0;
    __u64 *counter;
    counter = bpf_map_lookup_elem(&pkt_counter, &key);
    if (counter)
    {
        (*counter)++;
    }
    return 0;
}

char _license[] SEC("license") = "MIT";