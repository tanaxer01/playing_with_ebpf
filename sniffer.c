// go:build ignore
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf.h>

#define MAX_CPUS 256

#define min(x, y) ((x) < (y) ? x : y)

char __license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, MAX_CPUS);
    __type(key, int);
    __type(value, __u32);
} xdp_perf_map SEC(".maps");

struct pkt_trace_metadata {
    __u32 ifindex;
    __u32 rx_queue;
    __u16 pkt_len;
    __u16 cap_len;
    __u16 flags;
    __u16 prog_index;
    int action;
} __packed;

struct {
    __u32 capture_if_ifindex;
    __u32 capture_snaplen;
    __u32 capture_prog_index;
} trace_config SEC(".data");

SEC("xdp/hook")
int xdp__hook(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct pkt_trace_metadata metadata;

    if (data >= data_end || trace_config.capture_if_ifindex != ctx->ingress_ifindex)
        return XDP_PASS;

    metadata.prog_index = trace_config.capture_prog_index;
    metadata.ifindex = ctx->ingress_ifindex;
    metadata.rx_queue = ctx->rx_queue_index;
    metadata.pkt_len = (__u16)(data_end - data);
    metadata.cap_len = min(metadata.pkt_len, trace_config.capture_snaplen);
    metadata.action = 0;
    metadata.flags = 0;

    bpf_perf_event_output(ctx, &xdp_perf_map, ((__u64)metadata.cap_len << 32) | BPF_F_CURRENT_CPU,
                          &metadata, sizeof(metadata));

    return XDP_PASS;
}
